package output_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/pkg/api/admin"
)

func TestPrintTable_CreateTenantResponse(t *testing.T) {
	tests := []struct {
		name    string
		resp    admin.CreateTenantResponse
		expRows []output.Row
	}{
		{
			name: "prints tenant with all fields",
			resp: admin.CreateTenantResponse{
				ID:        "tenant-123",
				Name:      "my-tenant",
				Labels:    map[string]string{"env": "prod"},
				CreatedAt: time.Now().UnixNano() - int64(5*time.Minute),
				UpdatedAt: time.Now().UnixNano() - int64(2*time.Minute),
			},
			expRows: []output.Row{
				{"ID": "tenant-123", "NAME": "my-tenant", "LABELS": "env=prod", "CREATED": "5m ago", "UPDATED": "2m ago"},
			},
		},
		{
			name: "handles nil labels",
			resp: admin.CreateTenantResponse{
				ID:        "tenant-456",
				Name:      "empty-labels",
				CreatedAt: time.Now().UnixNano() - int64(1*time.Minute),
				UpdatedAt: time.Now().UnixNano() - int64(1*time.Minute),
			},
			expRows: []output.Row{
				{"ID": "tenant-456", "NAME": "empty-labels", "LABELS": "<none>", "CREATED": "1m ago", "UPDATED": "1m ago"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer

			// when
			err := output.PrintTable(&buf, tt.resp)

			// then
			assert.NoError(t, err)
			table := output.ParseTable(buf.Bytes())
			assert.Equal(t, output.TenantTable{}.Header(), table.Header)
			assert.Equal(t, tt.expRows, table.Rows)
		})
	}
}

func TestPrintTable_GetTenantResponse(t *testing.T) {
	tests := []struct {
		name    string
		resp    admin.GetTenantResponse
		expRows []output.Row
	}{
		{
			name: "prints tenant with all fields",
			resp: admin.GetTenantResponse{
				ID:        "tenant-789",
				Name:      "fetched-tenant",
				Labels:    map[string]string{"region": "eu"},
				CreatedAt: time.Now().UnixNano() - int64(1*time.Hour),
				UpdatedAt: time.Now().UnixNano() - int64(30*time.Minute),
			},
			expRows: []output.Row{
				{"ID": "tenant-789", "NAME": "fetched-tenant", "LABELS": "region=eu", "CREATED": "1h ago", "UPDATED": "30m ago"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer

			// when
			err := output.PrintTable(&buf, tt.resp)

			// then
			assert.NoError(t, err)
			table := output.ParseTable(buf.Bytes())
			assert.Equal(t, output.TenantTable{}.Header(), table.Header)
			assert.Equal(t, tt.expRows, table.Rows)
		})
	}
}

func TestPrintTable_ListTenantsResponse(t *testing.T) {
	tests := []struct {
		name    string
		resp    admin.ListTenantsResponse
		expRows []output.Row
	}{
		{
			name: "prints multiple tenants",
			resp: admin.ListTenantsResponse{
				Tenants: []admin.GetTenantResponse{
					{ID: "id-1", Name: "tenant-1", Labels: map[string]string{"env": "dev"}, CreatedAt: time.Now().UnixNano() - int64(1*time.Minute), UpdatedAt: time.Now().UnixNano() - int64(1*time.Minute)},
					{ID: "id-2", Name: "tenant-2", Labels: map[string]string{"env": "prod"}, CreatedAt: time.Now().UnixNano() - int64(2*time.Minute), UpdatedAt: time.Now().UnixNano() - int64(2*time.Minute)},
				},
			},
			expRows: []output.Row{
				{"ID": "id-1", "NAME": "tenant-1", "LABELS": "env=dev", "CREATED": "1m ago", "UPDATED": "1m ago"},
				{"ID": "id-2", "NAME": "tenant-2", "LABELS": "env=prod", "CREATED": "2m ago", "UPDATED": "2m ago"},
			},
		},
		{
			name:    "prints only header for empty list",
			resp:    admin.ListTenantsResponse{Tenants: []admin.GetTenantResponse{}},
			expRows: []output.Row{},
		},
		{
			name:    "prints only header for nil tenants",
			resp:    admin.ListTenantsResponse{Tenants: nil},
			expRows: []output.Row{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var buf bytes.Buffer

			// when
			err := output.PrintTable(&buf, tt.resp)

			// then
			assert.NoError(t, err)
			table := output.ParseTable(buf.Bytes())
			assert.Equal(t, output.TenantTable{}.Header(), table.Header)
			assert.Equal(t, tt.expRows, table.Rows)
		})
	}
}

func TestPrintTable_UnsupportedType(t *testing.T) {
	// given
	var buf bytes.Buffer

	// when
	err := output.PrintTable(&buf, "unsupported string type")

	// then
	assert.Error(t, err)
	assert.Empty(t, buf.String(), "should not print anything for unsupported types")
}
