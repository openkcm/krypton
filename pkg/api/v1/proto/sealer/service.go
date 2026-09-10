package sealer

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

const ciphertextKey = "ciphertext"
const plaintextKey = "plaintext"

// SealerService implements the gRPC [ServiceServer] for seal and unseal operations.
// It delegates cryptographic work to the underlying [cryptor.Sealer] and uses
// secure memory to protect sensitive data (plaintext, ciphertext) from leaking
// into swap or core dumps.
type SealerService struct {
	UnimplementedServiceServer

	sealer cryptor.Sealer
}

// NewSealerService creates a new [SealerService] backed by the given [cryptor.Sealer].
func NewSealerService(sealer cryptor.Sealer) *SealerService {
	return &SealerService{
		sealer: sealer,
	}
}

var _ ServiceServer = (*SealerService)(nil)

var (
	ErrInvalidTenantID   = errors.New("tenant ID is required")
	ErrInvalidKeyID      = errors.New("key ID is required")
	ErrInvalidKeyVersion = errors.New("key version must be greater than 0")
	ErrInvalidPlaintext  = errors.New("plaintext is required")
	ErrInvalidCiphertext = errors.New("ciphertext is required")
	ErrInvalidAAD        = errors.New("AAD is required")
)

// Seal implements [ServiceServer].
// It copies the request plaintext into secure memory, zeroes the original,
// delegates to the underlying sealer, and returns the ciphertext.
func (s *SealerService) Seal(ctx context.Context, req *SealRequest) (*SealResponse, error) {
	err := validateSealRequest(req)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}
	resp, err := securemem.Run(ctx, func(ctx context.Context, hReq *securemem.HandlerRequest) error {
		sPlnTxt, err := securemem.NewData(plaintextKey, len(req.GetPlaintext()))
		if err != nil {
			slog.Error("failed to allocate secure memory for plaintext", "error", err)
			return proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to process the plaintext"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}

		defer sPlnTxt.Destroy()

		copy(sPlnTxt.SecureBytes(), req.GetPlaintext())

		securemem.Zero(req.GetPlaintext())

		resp, err := s.sealer.Seal(ctx, cryptor.SealRequest{
			TenantID:   req.GetTenantId(),
			KeyID:      req.GetKeyId(),
			KeyVersion: int(req.GetKeyVersion()),
			Plaintext:  sPlnTxt,
			AAD:        req.GetAad(),
		})
		if err != nil {
			slog.Error("failed to seal the plaintext", "error", err)
			return proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to seal the plaintext"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}

		err = vaultImport(hReq.PersistentVault(), ciphertextKey, resp.Ciphertext)
		if err != nil {
			slog.Error("failed to import the ciphertext into the vault", "error", err)
			return proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to import the ciphertext into the vault"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	sCpTxt, ok := resp.MemVault().Get(ciphertextKey)
	if !ok {
		slog.Error("failed to get the ciphertext from the vault")
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get the ciphertext from the vault"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	return &SealResponse{
		Ciphertext: sCpTxt.SecureBytes(),
	}, nil
}

// Unseal implements [ServiceServer].
// It copies the request ciphertext into secure memory, zeroes the original,
// delegates to the underlying sealer, and returns the plaintext.
func (s *SealerService) Unseal(ctx context.Context, req *UnsealRequest) (*UnsealResponse, error) {
	err := validateUnsealRequest(req)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	resp, err := securemem.Run(ctx, func(ctx context.Context, hReq *securemem.HandlerRequest) error {
		sCpTxt, err := securemem.NewData(ciphertextKey, len(req.GetCiphertext()))
		if err != nil {
			slog.Error("failed to allocate secure memory for ciphertext", "error", err)
			return proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to process the ciphertext"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}

		defer sCpTxt.Destroy()

		copy(sCpTxt.SecureBytes(), req.GetCiphertext())

		securemem.Zero(req.GetCiphertext())

		resp, err := s.sealer.Unseal(ctx, cryptor.UnsealRequest{
			TenantID:   req.GetTenantId(),
			KeyID:      req.GetKeyId(),
			KeyVersion: int(req.GetKeyVersion()),
			Ciphertext: sCpTxt,
			AAD:        req.GetAad(),
		})
		if err != nil {
			slog.Error("failed to unseal the ciphertext", "error", err)
			return proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to unseal the ciphertext"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}

		err = vaultImport(hReq.PersistentVault(), plaintextKey, resp.Plaintext)
		if err != nil {
			slog.Error("failed to import the plaintext into the vault", "error", err)
			return proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to import the plaintext into the vault"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	sPlnTxt, ok := resp.MemVault().Get(plaintextKey)
	if !ok {
		slog.Error("failed to get the plaintext from the vault")
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get the plaintext from the vault"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	return &UnsealResponse{
		Plaintext: sPlnTxt.SecureBytes(),
	}, nil
}

// validateSealRequest checks that all required fields are present in the [SealRequest].
// It returns a joined error containing all validation failures, or nil if the request is valid.
func validateSealRequest(req *SealRequest) error {
	var errs []error
	if req.GetTenantId() == "" {
		errs = append(errs, ErrInvalidTenantID)
	}
	if req.GetKeyId() == "" {
		errs = append(errs, ErrInvalidKeyID)
	}
	if req.GetKeyVersion() <= 0 {
		errs = append(errs, ErrInvalidKeyVersion)
	}
	if len(req.GetPlaintext()) == 0 {
		errs = append(errs, ErrInvalidPlaintext)
	}
	if len(req.GetAad()) == 0 {
		errs = append(errs, ErrInvalidAAD)
	}
	return errors.Join(errs...)
}

// validateUnsealRequest checks that all required fields are present in the [UnsealRequest].
// It returns a joined error containing all validation failures, or nil if the request is valid.
func validateUnsealRequest(req *UnsealRequest) error {
	var errs []error
	if req.GetTenantId() == "" {
		errs = append(errs, ErrInvalidTenantID)
	}
	if req.GetKeyId() == "" {
		errs = append(errs, ErrInvalidKeyID)
	}
	if req.GetKeyVersion() <= 0 {
		errs = append(errs, ErrInvalidKeyVersion)
	}
	if len(req.GetCiphertext()) == 0 {
		errs = append(errs, ErrInvalidCiphertext)
	}
	if len(req.GetAad()) == 0 {
		errs = append(errs, ErrInvalidAAD)
	}
	return errors.Join(errs...)
}

// vaultImport stores a [securemem.Data] entry in the vault under the given name.
// If the import fails, the data is destroyed to prevent memory leaks.
func vaultImport(vault *securemem.MemVault, name string, data *securemem.Data) error {
	err := vault.Import(name, data)
	if err != nil {
		_ = data.Destroy()
	}
	return err
}
