package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

func (c *Client) CreateTenant(ctx context.Context, req CreateTenantRequest) (CreateTenantResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return CreateTenantResponse{}, fmt.Errorf("%w: %w", ErrFailedToEncodeRequest, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+PathTenants, bytes.NewReader(body))
	if err != nil {
		return CreateTenantResponse{}, fmt.Errorf("%w: %w", ErrFailedToCreateRequest, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return CreateTenantResponse{}, fmt.Errorf("%w: %w", ErrFailedToSendRequest, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusCreated {
		return CreateTenantResponse{}, fmt.Errorf("%w: expected 201 Created, got %d", ErrUnexpectedStatusCode, httpResp.StatusCode)
	}

	var resp CreateTenantResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return CreateTenantResponse{}, fmt.Errorf("%w: %w", ErrFailedToDecodeResponse, err)
	}

	return resp, nil
}

func (c *Client) GetTenant(ctx context.Context, req GetTenantRequest) (GetTenantResponse, error) {
	url := c.baseURL + strings.Replace(PathTenantByID, "{id}", req.ID, 1)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return GetTenantResponse{}, fmt.Errorf("%w: %w", ErrFailedToCreateRequest, err)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return GetTenantResponse{}, fmt.Errorf("%w: %w", ErrFailedToSendRequest, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusNotFound {
		return GetTenantResponse{}, ErrTenantNotFound
	}

	if httpResp.StatusCode != http.StatusOK {
		return GetTenantResponse{}, fmt.Errorf("%w: expected 200 OK, got %d", ErrUnexpectedStatusCode, httpResp.StatusCode)
	}

	var resp GetTenantResponse
	err = json.NewDecoder(httpResp.Body).Decode(&resp)
	if err != nil {
		return GetTenantResponse{}, fmt.Errorf("%w: %w", ErrFailedToDecodeResponse, err)
	}

	return resp, nil
}
