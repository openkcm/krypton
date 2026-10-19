package store_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

func TestValidateGetDescendantKeysQuery(t *testing.T) {
	tts := []struct {
		name   string
		subj   store.GetDescendantKeysQuery
		expErr error
	}{
		{
			name: "should fail when KeyID is empty",
			subj: store.GetDescendantKeysQuery{
				KeyID:    "",
				TenantID: uuid.New().String(),
				Filters:  []store.KeyFilter{},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should fail when KeyID is not valid UUID",
			subj: store.GetDescendantKeysQuery{
				KeyID:    "invalid-uuid",
				TenantID: uuid.New().String(),
				Filters:  []store.KeyFilter{},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should fail when TenantID is empty",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: "",
				Filters:  []store.KeyFilter{},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should fail when TenantID is not valid UUID",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: "invalid-uuid",
				Filters:  []store.KeyFilter{},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should fail if some filters have invalid lifecycle state",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						LifeCycleState: "invalue-state",
					},
				},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should fail if some filters have invalid status",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						Status: []model.KeyProcessingStatus{
							"invalid-status",
						},
					},
				},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should be successful when keyID and tenantID are valid UUIDs",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters:  []store.KeyFilter{},
			},
			expErr: nil,
		},
		{
			name: "should be successful when filters have valid lifecycle state",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						LifeCycleState: model.KeyLifeCycleDeactivated, // valid state
					},
				},
			},
			expErr: nil,
		},
		{
			name: "should be successful when filters have valid status",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						Status: []model.KeyProcessingStatus{
							model.KeyProcessingCompleted, // valid status
						},
					},
				},
			},
			expErr: nil,
		},
		{
			name: "should be successful when filters have valid empy status",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						Status: []model.KeyProcessingStatus{},
					},
				},
			},
			expErr: nil,
		},
		{
			name: "should be successful when filters have valid nil status",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters:  nil,
			},
			expErr: nil,
		},
		{
			name: "should fail when second filter has invalid lifecycle state",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						LifeCycleState: model.KeyLifeCycleActive, // valid
					},
					{
						LifeCycleState: "invalid-state", // invalid
					},
				},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should fail when second filter has invalid status",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						Status: []model.KeyProcessingStatus{
							model.KeyProcessingCompleted, // valid
						},
					},
					{
						Status: []model.KeyProcessingStatus{
							"invalid-status", // invalid
						},
					},
				},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should be successful when filter has both valid lifecycle state and valid status",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						LifeCycleState: model.KeyLifeCycleActive,
						Status: []model.KeyProcessingStatus{
							model.KeyProcessingCompleted,
						},
					},
				},
			},
			expErr: nil,
		},
		{
			name: "should fail when filter has valid lifecycle state but invalid status",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						LifeCycleState: model.KeyLifeCycleActive,
						Status: []model.KeyProcessingStatus{
							"invalid-status",
						},
					},
				},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should fail when second status in a filter is invalid",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						Status: []model.KeyProcessingStatus{
							model.KeyProcessingPending, // valid
							"invalid-status",           // invalid
						},
					},
				},
			},
			expErr: store.ErrInvalidQuery,
		},
		{
			name: "should be successful when filter has empty lifecycle state and valid statuses",
			subj: store.GetDescendantKeysQuery{
				KeyID:    uuid.New().String(),
				TenantID: uuid.New().String(),
				Filters: []store.KeyFilter{
					{
						LifeCycleState: "", // zero value, should be skipped
						Status: []model.KeyProcessingStatus{
							model.KeyProcessingPending,
							model.KeyProcessingCompleted,
						},
					},
				},
			},
			expErr: nil,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// given

			// when
			err := tt.subj.Validate()

			// then
			assert.ErrorIs(t, err, tt.expErr)
		})
	}
}
