package store

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/spec"
)

var ErrRegistryNotFound = errors.New("registry not found")

type Registry interface {
	Upsert(ctx context.Context, registry UpsertRegistryQuery) (UpsertRegistryResult, error)
	Get(ctx context.Context, registry GetRegistryQuery) (GetRegistryResult, error)
}

type (
	UpsertRegistryQuery struct {
		Registry spec.Registry
	}

	UpsertRegistryResult struct {
		Registry spec.Registry
	}

	GetRegistryQuery struct {
		Name       string
		InstanceID string
	}

	GetRegistryResult struct {
		Registry spec.Registry
	}
)
