package admin

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
		Id:             k.ID,
		Name:           k.Name,
		TenantId:       k.TenantID,
		Kind:           string(k.Kind),
		ParentId:       parentID,
		ManagedBy:      k.ManagedBy,
		Labels:         k.Labels,
		LifeCycleState: string(k.LifeCycleState),
		KeyProcessingState: &KeyProcessingState{
			Status: k.KeyProcessingState.Status,
			JobId:  k.KeyProcessingState.JobID,
		},
		CreatedAt: int64(k.CreatedAt),
		UpdatedAt: int64(k.UpdatedAt),
	}
}

func KeyTreeToProto(tree model.KeyTreeTraverser) []*KeyTree {
	var res []*KeyTree
	for layer := range tree.IterKeysByLayerAsc() {
		res = append(res, &KeyTree{Keys: KeysToProto(layer)})
	}
	return res
}

func KeysToProto(ks []model.Key) []*Key {
	res := make([]*Key, len(ks))
	for i := range ks {
		res[i] = KeyToProto(ks[i])
	}
	return res
}

func KeyFromProto(k *Key) model.Key {
	var parentID *string
	if pid := k.GetParentId(); pid != "" {
		parentID = &pid
	}
	processingState := model.KeyProcessingState{}
	if ps := k.GetKeyProcessingState(); ps != nil {
		processingState.Status = ps.GetStatus()
		processingState.JobID = ps.GetJobId()
	}
	return model.Key{
		ID:                 k.GetId(),
		Name:               k.GetName(),
		TenantID:           k.GetTenantId(),
		Kind:               model.KeyKind(k.GetKind()),
		ParentID:           parentID,
		ManagedBy:          k.GetManagedBy(),
		Labels:             k.GetLabels(),
		LifeCycleState:     model.KeyLifeCycleState(k.GetLifeCycleState()),
		KeyProcessingState: processingState,
		CreatedAt:          clock.UnixNano(k.GetCreatedAt()),
		UpdatedAt:          clock.UnixNano(k.GetUpdatedAt()),
	}
}
