package cmd

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/pkg/authn"
	"github.com/openkcm/krypton/pkg/authn/provider"
	"github.com/openkcm/krypton/pkg/authn/store"
)

// errNotValidStatus is returned when the token is not valid.
var errNotValidStatus = errors.New("token is not valid, please login again")

// newConnection creates a new gRPC connection to the server using the token stored in the store.
func newConnection(ctx context.Context, serverAddr string) (*grpc.ClientConn, error) {
	fs, err := store.NewFS()
	if err != nil {
		return nil, err
	}

	tkn, err := fs.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token from store: %w", err)
	}

	var opts []grpc.DialOption

	switch tkn.Type {
	case authn.MTLS:
		err = isValid(ctx, &provider.MTLS{}, tkn)
		if err != nil {
			return nil, err
		}

		creds, err := provider.NewMTLSCredentialsValue(tkn.Value)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal token value: %w", err)
		}

		tlsCfg, err := creds.TLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create tls config: %w", err)
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	case authn.NoAuth:
		err = isValid(ctx, &provider.NoOp{}, tkn)
		if err != nil {
			return nil, err
		}

		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	default:
		return nil, fmt.Errorf("unsupported token type: %s", tkn.Type)
	}

	return grpc.NewClient(
		serverAddr,
		opts...,
	)
}

func isValid(ctx context.Context, prv authn.Provider, tkn *authn.Token) error {
	status, err := prv.Validate(ctx, tkn)
	if err != nil {
		return fmt.Errorf("failed to validate token: %w", err)
	}
	if status.Status != authn.ValidStatus {
		return errNotValidStatus
	}
	return nil
}
