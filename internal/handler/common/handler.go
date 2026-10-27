package common

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

func ValidateTenantID(tenantID string) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		err := validator.ValidateTenant(tenantID)(ctx, stores)
		if err == nil {
			return nil
		}
		if errors.Is(err, store.ErrTenantNotFound) {
			return OrbitalFail(err)
		}
		return OrbitalContinue(err)
	}
}

func EnsureKey(kid handler.KeyIdentifier, cond func(key *model.Key) bool) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		key, err := stores.Keys.GetKeyByID(ctx, kid.ID, kid.TenantID)
		if err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				return OrbitalFail(err)
			}
			return OrbitalContinue(err)
		}

		if cond != nil && !cond(key) {
			return OrbitalComplete()
		}
		return nil
	}
}
