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

// Client is an HTTP client for the krypton agent API.
type Client struct {
	baseURL   string
	agentName string
	agentID   string
	cli       *krhttp.Client
}

var (
	// ErrAgentNameEmpty is returned when the agent name is empty.
	ErrAgentNameEmpty = errors.New("agent name cannot be empty")
	// ErrAgentTopologyNotFound is returned when the agent is not in the topology.
	ErrAgentTopologyNotFound = errors.New("agent not found in topology")
	// ErrAgentIDEmpty is returned when the agent ID is empty.
	ErrAgentIDEmpty = errors.New("agent ID cannot be empty")
)

// NewClient creates a new Client. Returns an error if any argument is empty.
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

// Register sends an agent registration request to the server.
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
		return RegisterResponse{}, ErrAgentTopologyNotFound
	default:
		return RegisterResponse{}, fmt.Errorf("%w: expected %d Created, got %d", api.ErrUnexpectedStatusCode, http.StatusOK, httpResp.StatusCode)
	}
}

// SendHeartbeat sends a heartbeat to signal the agent is alive.
func (c *Client) SendHeartbeat(ctx context.Context, req SendHeartbeatRequest) (SendHeartbeatResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return SendHeartbeatResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToEncodeRequest, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+PathHeartbeat, bytes.NewReader(body))
	if err != nil {
		return SendHeartbeatResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToCreateRequest, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(AgentNameHeader, c.agentName)
	httpReq.Header.Set(AgentIDHeader, c.agentID)

	httpResp, err := c.cli.Do(httpReq)
	if err != nil {
		return SendHeartbeatResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToSendRequest, err)
	}
	defer httpResp.Body.Close()

	switch httpResp.StatusCode {
	case http.StatusOK:
		var resp SendHeartbeatResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		if err != nil {
			return SendHeartbeatResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToDecodeResponse, err)
		}
		return resp, nil
	case http.StatusNotFound:
		return SendHeartbeatResponse{}, ErrAgentTopologyNotFound
	default:
		return SendHeartbeatResponse{}, fmt.Errorf("%w: expected %d Created, got %d", api.ErrUnexpectedStatusCode, http.StatusOK, httpResp.StatusCode)
	}
}

func (c *Client) Deregister(ctx context.Context, req DeregisterRequest) (DeregisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return DeregisterResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToEncodeRequest, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+PathDeregister, bytes.NewReader(body))
	if err != nil {
		return DeregisterResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToCreateRequest, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(AgentNameHeader, c.agentName)
	httpReq.Header.Set(AgentIDHeader, c.agentID)

	httpResp, err := c.cli.Do(httpReq)
	if err != nil {
		return DeregisterResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToSendRequest, err)
	}
	defer httpResp.Body.Close()

	switch httpResp.StatusCode {
	case http.StatusOK:
		var resp DeregisterResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		if err != nil {
			return DeregisterResponse{}, fmt.Errorf("%w: %w", api.ErrFailedToDecodeResponse, err)
		}
		return resp, nil
	default:
		return DeregisterResponse{}, fmt.Errorf("%w: expected %d Created, got %d", api.ErrUnexpectedStatusCode, http.StatusOK, httpResp.StatusCode)
	}
}
