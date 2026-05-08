package keys

import (
	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/model"
)

func KeyToProto(k model.Key) *Key {
	var parentID string
	if k.ParentID != nil {
		parentID = *k.ParentID
	}
	return &Key{
		Id:        k.ID,
		Name:      k.Name,
		TenantId:  k.TenantID,
		Kind:      k.Kind,
		ParentId:  parentID,
		ManagedBy: k.ManagedBy,
		Labels:    k.Labels,
		State:     string(k.State),
		CreatedAt: int64(k.CreatedAt),
		UpdatedAt: int64(k.UpdatedAt),
	}
}

func KeyFromProto(k *Key) model.Key {
	var parentID *string
	if k.GetParentId() != "" {
		p := k.GetParentId()
		parentID = &p
	}
	return model.Key{
		ID:        k.GetId(),
		Name:      k.GetName(),
		TenantID:  k.GetTenantId(),
		Kind:      k.GetKind(),
		ParentID:  parentID,
		ManagedBy: k.GetManagedBy(),
		Labels:    k.GetLabels(),
		State:     model.KeyState(k.GetState()),
		CreatedAt: clock.UnixNano(k.GetCreatedAt()),
		UpdatedAt: clock.UnixNano(k.GetUpdatedAt()),
	}
}
