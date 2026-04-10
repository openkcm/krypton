package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/openkcm/krypton/internal/krhttp"
	"github.com/openkcm/krypton/pkg/api"
)

type Client struct {
	baseURL   string
	agentName string
	agentID   string
	cli       *krhttp.Client
}

var (
	ErrAgentNameEmpty = errors.New("agent name cannot be empty")
	ErrAgentNotFound  = errors.New("agent not found in topology")
	ErrAgentIDEmpty   = errors.New("agent ID cannot be empty")
)

// NewClient creates a new Client with the given base URL and agent name.
func NewClient(baseURL, agentName, agentID string) (*Client, error) {
	if agentName == "" {
		return nil, ErrAgentNameEmpty
	}
	if agentID == "" {
		return nil, ErrAgentIDEmpty
	}

	if baseURL == "" {
		return nil, api.ErrBaseURLEmpty
	}
	return &Client{
		baseURL:   baseURL,
		agentName: agentName,
		agentID:   agentID,
		cli:       krhttp.NewClient(),
	}, nil
}

// Register sends a agent registration request to the server and returns the response.
func (c *Client) Register(ctx context.Context, req RegisterRequest) (RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToEncodeRequest, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+PathRegister, bytes.NewReader(body))
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToCreateRequest, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(AgentNameHeader, c.agentName)
	httpReq.Header.Set(AgentIDHeader, c.agentID)

	httpResp, err := c.cli.Do(httpReq)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToSendRequest, err)
	}
	defer httpResp.Body.Close()

	switch httpResp.StatusCode {
	case http.StatusOK:
		var resp RegisterResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		if err != nil {
			return RegisterResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToDecodeResponse, err)
		}
		return resp, nil
	case http.StatusNotFound:
		return RegisterResponse{}, ErrAgentNotFound
	default:
		return RegisterResponse{}, fmt.Errorf("%w: expected %d Created, got %d", api.ErrUnexpectedStatusCode, http.StatusOK, httpResp.StatusCode)
	}
}
