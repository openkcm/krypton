package sealer

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

type SealerService struct {
	UnimplementedServiceServer

	manager cryptor.Sealer
}

func NewSealerService(manager cryptor.Sealer) *SealerService {
	return &SealerService{
		manager: manager,
	}
}

type handlerVault struct{}

var _ ServiceServer = (*SealerService)(nil)

// Seal implements [ServiceServer].
func (s *SealerService) Seal(ctx context.Context, req *SealRequest) (*SealResponse, error) {
	// create securemem.Data from plaintext
	rData, err := securemem.NewData("request", len(req.GetPlaintext()))
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to process the plaintext"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	// copy the plaintext into the securemem.Data
	copy(rData.SecureBytes(), req.GetPlaintext())

	// clear the request bytes
	securemem.Zero(req.GetPlaintext())

	vault := securemem.NewMemVault()

	// TODO: will be destroyed in post hook
	ctx = VaultToContext(ctx, vault)

	// import the securemem.Data into the vault for tracking
	err = vaultImport(vault, "input", rData)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to import the plaintext into the vault"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	resp, err := s.manager.Seal(ctx, cryptor.SealRequest{
		TenantID:   req.GetTenantId(),
		KeyID:      req.GetKeyId(),
		KeyVersion: int(req.GetKeyVersion()),
		Plaintext:  rData,
		AAD:        req.GetAad(),
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to seal the plaintext"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	err = vaultImport(vault, "output", resp.Ciphertext)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to import the ciphertext into the vault"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	return &SealResponse{
		Ciphertext: resp.Ciphertext.SecureBytes(),
	}, nil
}

// Unseal implements [ServiceServer].
func (s *SealerService) Unseal(ctx context.Context, req *UnsealRequest) (*UnsealResponse, error) {
	// create securemem.Data from ciphertext
	rData, err := securemem.NewData("request", len(req.GetCiphertext()))
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to process the ciphertext"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	// copy the ciphertext into the securemem.Data
	copy(rData.SecureBytes(), req.GetCiphertext())

	// clear the request bytes
	securemem.Zero(req.GetCiphertext())

	vault := securemem.NewMemVault()

	// TODO: will be destroyed in post hook
	ctx = VaultToContext(ctx, vault)

	// import the securemem.Data into the vault for tracking
	err = vaultImport(vault, "input", rData)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to import the ciphertext into the vault"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	resp, err := s.manager.Unseal(ctx, cryptor.UnsealRequest{
		TenantID:   req.GetTenantId(),
		KeyID:      req.GetKeyId(),
		KeyVersion: int(req.GetKeyVersion()),
		Ciphertext: rData,
		AAD:        req.GetAad(),
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to unseal the ciphertext"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	err = vaultImport(vault, "output", resp.Plaintext)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to import the plaintext into the vault"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	return &UnsealResponse{
		Plaintext: resp.Plaintext.SecureBytes(),
	}, nil
}

func VaultFromContext(ctx context.Context) (*securemem.MemVault, bool) {
	res, ok := ctx.Value(handlerVault{}).(*securemem.MemVault)
	return res, ok
}

func VaultToContext(ctx context.Context, vault *securemem.MemVault) context.Context {
	return context.WithValue(ctx, handlerVault{}, vault)
}

func vaultImport(vault *securemem.MemVault, name string, data *securemem.Data) error {
	err := vault.Import(name, data)
	if err != nil {
		_ = data.Destroy()
	}
	return err
}
