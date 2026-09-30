package activatekey

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/pkg/store"
)

// ErrNoKeys is returned when the target key resolves to no keys to activate.
var ErrNoKeys = errors.New("no keys to activate")

// BuildJobGroup walks the target key's hierarchy (the key itself plus all its
// descendants, grouped by depth) and builds one job group with one job per
// layer, ordered root to leaf. Orbital runs the jobs sequentially in this order
// and fails the whole group if any layer fails, giving the "layers sequential,
// failed layer stops the cascade" semantics for free.
func BuildJobGroup(ctx context.Context, keyStore store.Key, tenantID, rootKeyID string) (orbital.JobGroup, error) {
	res, err := keyStore.GetDescendantKeys(ctx, store.GetDescendantKeysQuery{
		KeyID:    rootKeyID,
		TenantID: tenantID,
	})
	if err != nil {
		// An unknown key has no hierarchy to activate — surface it as ErrNoKeys
		// so callers can report "not found" rather than an internal error.
		if errors.Is(err, store.ErrKeyNotFound) {
			return orbital.JobGroup{}, ErrNoKeys
		}
		return orbital.JobGroup{}, fmt.Errorf("get descendant keys: %w", err)
	}

	var jobs []orbital.Job
	for layer := range res.KeyTree.IterKeysByLayerAsc() {
		keyIDs := make([]string, 0, len(layer))
		for _, key := range layer {
			keyIDs = append(keyIDs, key.ID)
		}
		if len(keyIDs) == 0 {
			continue
		}

		data, err := json.Marshal(LayerData{
			TenantID:  tenantID,
			RootKeyID: rootKeyID,
			KeyIDs:    keyIDs,
		})
		if err != nil {
			return orbital.JobGroup{}, fmt.Errorf("marshal layer data: %w", err)
		}
		jobs = append(jobs, orbital.NewJob(JobType, data))
	}

	if len(jobs) == 0 {
		return orbital.JobGroup{}, ErrNoKeys
	}

	return orbital.NewJobGroup(GroupType, jobs...), nil
}
