package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openkcm/krypton/pkg/model"
)

var (
	ErrFailedToEncodeRequest  = errors.New("failed to encode request")
	ErrFailedToCreateRequest  = errors.New("failed to create request")
	ErrFailedToSendRequest    = errors.New("failed to send request")
	ErrUnexpectedStatusCode   = errors.New("unexpected status code")
	ErrFailedToDecodeResponse = errors.New("failed to decode response")
	ErrTenantNotFound         = errors.New("tenant not found")
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Krypton admin API client.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL:    baseURL,
		httpClient: http.DefaultClient,
	}
}

func (c *Client) CreateTenant(ctx context.Context, req CreateTenantRequest) (model.Tenant, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("%w: %w", ErrFailedToEncodeRequest, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+PathTenants, bytes.NewReader(body))
	if err != nil {
		return model.Tenant{}, fmt.Errorf("%w: %w", ErrFailedToCreateRequest, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("%w: %w", ErrFailedToSendRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return model.Tenant{}, fmt.Errorf("%w: expected 201 Created, got %d", ErrUnexpectedStatusCode, resp.StatusCode)
	}

	var tenant model.Tenant
	err = json.NewDecoder(resp.Body).Decode(&tenant)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("%w: %w", ErrFailedToDecodeResponse, err)
	}

	return tenant, nil
}

func (c *Client) GetTenant(ctx context.Context, id string) (model.Tenant, error) {
	url := c.baseURL + strings.Replace(PathTenantByID, "{id}", id, 1)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("%w: %w", ErrFailedToCreateRequest, err)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("%w: %w", ErrFailedToSendRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return model.Tenant{}, ErrTenantNotFound
	}

	if resp.StatusCode != http.StatusOK {
		return model.Tenant{}, fmt.Errorf("%w: expected 200 OK, got %d", ErrUnexpectedStatusCode, resp.StatusCode)
	}

	var tenant model.Tenant
	err = json.NewDecoder(resp.Body).Decode(&tenant)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("%w: %w", ErrFailedToDecodeResponse, err)
	}

	return tenant, nil
}
