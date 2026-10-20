package handler

type KeyLayer struct {
	Identifiers []KeyIdentifier `json:"identifiers"`
}

type KeyIdentifier struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
}
