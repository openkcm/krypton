package orchestrator

// KeyLayer groups key identifiers that belong to the same tree layer.
// It is serialized as orbital job data.
type KeyLayer struct {
	Identifiers []KeyIdentifier `json:"identifiers"`
}

// KeyIdentifier locates a single key by its ID and tenant.
type KeyIdentifier struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}
