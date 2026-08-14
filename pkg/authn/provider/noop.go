package provider

import (
	"context"

	"github.com/openkcm/krypton/pkg/authn"
)

type NoOp struct{}

var _ authn.Provider = &NoOp{}

func (n *NoOp) Verify(ctx context.Context, c *authn.Credentials) (*authn.Token, error) {
	return &authn.Token{Type: authn.NoAuth}, nil
}

func (n *NoOp) Validate(ctx context.Context, s *authn.Token) (authn.ValidationResult, error) {
	if s.Type != authn.NoAuth {
		return authn.ValidationResult{
			Status: authn.InvalidStatus,
		}, nil
	}
	return authn.ValidationResult{
		Status: authn.ValidStatus,
	}, nil
}
