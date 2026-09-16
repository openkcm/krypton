package keyprocessor

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
)

const (
	handlerKey = "handlerKey"
)

// RPCManager is a [cryptor.Sealer] that delegates seal and unseal operations
// to a remote agent over gRPC.
type RPCManager struct {
	sealer sealer.ServiceClient
}

var _ cryptor.Sealer = (*RPCManager)(nil)

func NewRPCManager(target string, tls config.AuthConfig) (*RPCManager, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}

	if tls != nil {
		mtlsCfg, err := config.GetAuthConfig(tls)
		if err != nil {
			return nil, err
		}

		tlsCfg, err := mtlsCfg.Client.BuildTLSConfig()
		if err != nil {
			return nil, err
		}

		opts[0] = grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	}

	conn, err := grpc.NewClient(
		target,
		opts...,
	)
	if err != nil {
		return nil, err
	}

	return &RPCManager{
		sealer: sealer.NewServiceClient(conn),
	}, nil
}

// Seal implements [cryptor.Sealer].
func (r *RPCManager) Seal(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, hreq *securemem.HandlerRequest) error {
		defer req.Plaintext.Destroy()

		resp, err := r.sealer.Seal(ctx, &sealer.SealRequest{
			TenantId:   req.TenantID,
			KeyId:      req.KeyID,
			KeyVersion: int32(req.KeyVersion),
			Plaintext:  req.Plaintext.SecureBytes(),
			Aad:        req.AAD,
		})
		if err != nil {
			slog.Error("failed to seal data", "error", err)
			return err
		}

		ctext, err := securemem.NewData("data", len(resp.GetCiphertext()))
		if err != nil {
			slog.Error("failed to allocate memory for ciphertext", "error", err)
			return err
		}

		copy(ctext.SecureBytes(), resp.GetCiphertext())

		securemem.Zero(resp.GetCiphertext())

		err = vaultImport(hreq.PersistentVault(), handlerKey, ctext)
		if err != nil {
			slog.Error("failed to import ciphertext into vault", "error", err)
			return err
		}

		return nil
	})
	if err != nil {
		slog.Error("failed to run secure memory operation", "error", err)
		return cryptor.SealResponse{}, err
	}

	ctext, ok := resp.MemVault().Get(handlerKey)
	if !ok {
		slog.Error("failed to retrieve ciphertext from vault")
		cleanHandlerResponse(resp)
		return cryptor.SealResponse{}, ErrSecNotPersisted
	}

	return cryptor.SealResponse{
		Ciphertext: ctext,
	}, nil
}

// Unseal implements [cryptor.Sealer].
func (r *RPCManager) Unseal(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, hreq *securemem.HandlerRequest) error {
		defer req.Ciphertext.Destroy()

		resp, err := r.sealer.Unseal(ctx, &sealer.UnsealRequest{
			TenantId:   req.TenantID,
			KeyId:      req.KeyID,
			KeyVersion: int32(req.KeyVersion),
			Ciphertext: req.Ciphertext.SecureBytes(),
			Aad:        req.AAD,
		})
		if err != nil {
			slog.Error("failed to unseal data", "error", err)
			return err
		}

		ptext, err := securemem.NewData("data", len(resp.GetPlaintext()))
		if err != nil {
			slog.Error("failed to allocate memory for plaintext", "error", err)
			return err
		}

		copy(ptext.SecureBytes(), resp.GetPlaintext())

		securemem.Zero(resp.GetPlaintext())

		err = vaultImport(hreq.PersistentVault(), handlerKey, ptext)
		if err != nil {
			slog.Error("failed to import plaintext into vault", "error", err)
			return err
		}

		return nil
	})
	if err != nil {
		slog.Error("failed to run secure memory operation", "error", err)
		return cryptor.UnsealResponse{}, err
	}

	ptext, ok := resp.MemVault().Get(handlerKey)
	if !ok {
		slog.Error("failed to retrieve plaintext from vault")
		cleanHandlerResponse(resp)
		return cryptor.UnsealResponse{}, ErrSecNotPersisted
	}

	return cryptor.UnsealResponse{
		Plaintext: ptext,
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
		return err
	}
	return nil
}

func cleanHandlerResponse(resp *securemem.HandlerResponse) {
	err := resp.MemVault().DestroyAll()
	if err != nil {
		slog.Error("failed to cleanup handler response vault", "error", err)
	}
}
