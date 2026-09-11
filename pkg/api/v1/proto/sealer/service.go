package sealer

import (
	"context"
	"errors"
	"log/slog"
	"uuid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

const (
	handlerKey = "handlerKey"
)

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

// Validation sentinel errors returned on invalid seal/unseal requests.
var (
	ErrInvalidTenantID   = errors.New("tenant ID must be a valid UUID")
	ErrInvalidKeyID      = errors.New("key ID must be a valid UUID")
	ErrInvalidKeyVersion = errors.New("key version must be greater than 0")
	ErrInvalidText       = errors.New("text is required")
	ErrInvalidAAD        = errors.New("AAD is required")
)

// Seal implements [ServiceServer]. It encrypts plaintext using secure memory
// and stores the result in the per-RPC context vault for automatic cleanup.
func (s *SealerService) Seal(ctx context.Context, req *SealRequest) (*SealResponse, error) {
	err := validateSealRequest(req)
	if err != nil {
		return nil, err
	}
	resp, err := securemem.Run(ctx, func(ctx context.Context, hReq *securemem.HandlerRequest) error {
		sptxt, err := newData(len(req.GetPlaintext()))
		if err != nil {
			slog.Error("failed to allocate secure memory for plaintext", "error", err)
			return err
		}

		defer sptxt.Destroy()

		copy(sptxt.SecureBytes(), req.GetPlaintext())

		securemem.Zero(req.GetPlaintext())

		resp, err := s.sealer.Seal(ctx, cryptor.SealRequest{
			TenantID:   req.GetTenantId(),
			KeyID:      req.GetKeyId(),
			KeyVersion: int(req.GetKeyVersion()),
			Plaintext:  sptxt,
			AAD:        req.GetAad(),
		})
		if err != nil {
			slog.Error("failed to seal the plaintext", "error", err)
			return proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to seal the plaintext"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}

		err = vaultImport(hReq.PersistentVault(), handlerKey, resp.Ciphertext)
		if err != nil {
			slog.Error("failed to import the ciphertext into the vault", "error", err)
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	sctxt, ok := resp.MemVault().Get(handlerKey)
	if !ok {
		slog.Error("failed to get the ciphertext from the vault")

		// destroy all data in the vault to prevent memory leaks
		cleanHandlerResponse(resp)

		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get the ciphertext from the vault"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	err = addToContextVault(ctx, sctxt)
	if err != nil {
		slog.Error("failed to add the ciphertext to the context vault", "error", err)

		// destroy all data in the vault to prevent memory leaks
		cleanHandlerResponse(resp)

		return nil, err
	}

	return &SealResponse{
		Ciphertext: sctxt.SecureBytes(),
	}, nil
}

// Unseal implements [ServiceServer]. It decrypts ciphertext using secure memory
// and stores the result in the per-RPC context vault for automatic cleanup.
func (s *SealerService) Unseal(ctx context.Context, req *UnsealRequest) (*UnsealResponse, error) {
	err := validateUnsealRequest(req)
	if err != nil {
		return nil, err
	}

	resp, err := securemem.Run(ctx, func(ctx context.Context, hReq *securemem.HandlerRequest) error {
		sctxt, err := newData(len(req.GetCiphertext()))
		if err != nil {
			slog.Error("failed to allocate secure memory for ciphertext", "error", err)
			return err
		}

		defer sctxt.Destroy()

		copy(sctxt.SecureBytes(), req.GetCiphertext())

		securemem.Zero(req.GetCiphertext())

		resp, err := s.sealer.Unseal(ctx, cryptor.UnsealRequest{
			TenantID:   req.GetTenantId(),
			KeyID:      req.GetKeyId(),
			KeyVersion: int(req.GetKeyVersion()),
			Ciphertext: sctxt,
			AAD:        req.GetAad(),
		})
		if err != nil {
			slog.Error("failed to unseal the ciphertext", "error", err)
			return proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to unseal the ciphertext"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}

		err = vaultImport(hReq.PersistentVault(), handlerKey, resp.Plaintext)
		if err != nil {
			slog.Error("failed to import the plaintext into the vault", "error", err)
			return err
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	sptxt, ok := resp.MemVault().Get(handlerKey)
	if !ok {
		slog.Error("failed to get the plaintext from the vault")

		// destroy all data in the vault to prevent memory leaks
		cleanHandlerResponse(resp)

		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get the plaintext from the vault"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	err = addToContextVault(ctx, sptxt)
	if err != nil {
		slog.Error("failed to add the plaintext to the context vault", "error", err)

		// destroy all data in the vault to prevent memory leaks
		cleanHandlerResponse(resp)

		return nil, err
	}

	return &UnsealResponse{
		Plaintext: sptxt.SecureBytes(),
	}, nil
}

// vaultImport stores a [securemem.Data] entry in the vault under the given name.
// If the import fails, the data is destroyed to prevent memory leaks.
func vaultImport(vault *securemem.MemVault, name string, data *securemem.Data) error {
	err := vault.Import(name, data)
	if err != nil {
		if dErr := data.Destroy(); dErr != nil {
			slog.Error("failed to destroy data after failed import", "error", dErr)
		}
		return proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to import into the vault"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}
	return nil
}

// addToContextVault transfers ownership of d to the per-RPC [securemem.MemVault]
// stored in ctx, so that the [securemem.RPCHandler] can destroy it when the RPC ends.
func addToContextVault(ctx context.Context, d *securemem.Data) error {
	memVault, ok := securemem.VaultFromContext(ctx)
	if !ok {
		return proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get the vault from the context"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}
	return vaultImport(memVault, uuid.New().String(), d)
}

func newData(size int) (*securemem.Data, error) {
	d, err := securemem.NewData("text", size)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to process the securemem data"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}
	return d, nil
}

func validateSealRequest(req *SealRequest) error {
	return validateRequest(req.GetTenantId(), req.GetKeyId(), req.GetKeyVersion(), req.GetPlaintext(), req.GetAad())
}

func validateUnsealRequest(req *UnsealRequest) error {
	return validateRequest(req.GetTenantId(), req.GetKeyId(), req.GetKeyVersion(), req.GetCiphertext(), req.GetAad())
}

func validateRequest(tenantID, keyID string, keyVersion int32, payload, aad []byte) error {
	var errs []error
	if validateUUID(tenantID) != nil {
		errs = append(errs, ErrInvalidTenantID)
	}
	if validateUUID(keyID) != nil {
		errs = append(errs, ErrInvalidKeyID)
	}
	if keyVersion <= 0 {
		errs = append(errs, ErrInvalidKeyVersion)
	}
	if len(payload) == 0 {
		errs = append(errs, ErrInvalidText)
	}
	if len(aad) == 0 {
		errs = append(errs, ErrInvalidAAD)
	}
	err := errors.Join(errs...)
	if err != nil {
		return proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}
	return nil
}

func validateUUID(s string) error {
	_, err := uuid.Parse(s)
	return err
}

func cleanHandlerResponse(resp *securemem.HandlerResponse) {
	err := resp.MemVault().DestroyAll()
	if err != nil {
		slog.Error("failed to cleanup handler response vault", "error", err)
	}
}
