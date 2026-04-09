package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openkcm/krypton/internal/krhttp"
	"github.com/openkcm/krypton/pkg/api"
)

var (
	ErrTenantNotFound = errors.New("tenant not found")
)

type Client struct {
	baseURL string
	cli     *krhttp.Client
}

// NewClient creates a new Krypton admin API client.
func NewClient(baseURL string) (*Client, error) {
	if baseURL == "" {
		return nil, api.ErrBaseURLEmpty
	}
	return &Client{
		baseURL: baseURL,
		cli:     krhttp.NewClient(),
	}, nil
}

func (c *Client) CreateTenant(ctx context.Context, req CreateTenantRequest) (CreateTenantResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return CreateTenantResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToEncodeRequest, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+PathTenants, bytes.NewReader(body))
	if err != nil {
		return CreateTenantResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToCreateRequest, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.cli.Do(httpReq)
	if err != nil {
		return CreateTenantResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToSendRequest, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusCreated {
		return CreateTenantResponse{}, fmt.Errorf("%w: expected 201 Created, got %d", api.ErrUnexpectedStatusCode, httpResp.StatusCode)
	}

	var resp CreateTenantResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return CreateTenantResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToDecodeResponse, err)
	}

	return resp, nil
}

func (c *Client) GetTenant(ctx context.Context, req GetTenantRequest) (GetTenantResponse, error) {
	url := c.baseURL + strings.Replace(PathTenantByID, "{id}", req.ID, 1)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return GetTenantResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToCreateRequest, err)
	}

	httpResp, err := c.cli.Do(httpReq)
	if err != nil {
		return GetTenantResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToSendRequest, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusNotFound {
		return GetTenantResponse{}, ErrTenantNotFound
	}

	if httpResp.StatusCode != http.StatusOK {
		return GetTenantResponse{}, fmt.Errorf("%w: expected 200 OK, got %d", api.ErrUnexpectedStatusCode, httpResp.StatusCode)
	}

	var resp GetTenantResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return GetTenantResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToDecodeResponse, err)
	}

	return resp, nil
}

func (c *Client) ListTenants(ctx context.Context, _ ListTenantsRequest) (ListTenantsResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+PathTenants, nil)
	if err != nil {
		return ListTenantsResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToCreateRequest, err)
	}

	httpResp, err := c.cli.Do(httpReq)
	if err != nil {
		return ListTenantsResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToSendRequest, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return ListTenantsResponse{}, fmt.Errorf("%w: expected 200 OK, got %d", api.ErrUnexpectedStatusCode, httpResp.StatusCode)
	}

	var resp ListTenantsResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return ListTenantsResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToDecodeResponse, err)
	}

	return resp, nil
}
