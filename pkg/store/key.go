package store

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/pkg/model"
)

var ErrKeyNotFound = errors.New("key not found")

type Key interface {
	CreateKey(ctx context.Context, key model.Key) error
	GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error)
}
