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
	var resp RegisterResponse
	hResp, err := c.doCall(ctx, PathRegister, req, &resp)
	if err != nil {
		return RegisterResponse{}, err
	}

	switch hResp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound:
		return RegisterResponse{}, ErrAgentTopologyNotFound
	default:
		return RegisterResponse{}, fmt.Errorf("%w: expected %d Created, got %d", api.ErrUnexpectedStatusCode, http.StatusOK, hResp.StatusCode)
	}
}

// SendHeartbeat sends a heartbeat to signal the agent is alive.
func (c *Client) SendHeartbeat(ctx context.Context, req SendHeartbeatRequest) (SendHeartbeatResponse, error) {
	var resp SendHeartbeatResponse
	hResp, err := c.doCall(ctx, PathHeartbeat, req, &resp)
	if err != nil {
		return SendHeartbeatResponse{}, err
	}

	switch hResp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound:
		return SendHeartbeatResponse{}, ErrAgentTopologyNotFound
	default:
		return SendHeartbeatResponse{}, fmt.Errorf("%w: expected %d Created, got %d", api.ErrUnexpectedStatusCode, http.StatusOK, hResp.StatusCode)
	}
}

func (c *Client) Deregister(ctx context.Context, req DeregisterRequest) (DeregisterResponse, error) {
	var resp DeregisterResponse
	hResp, err := c.doCall(ctx, PathDeregister, req, &resp)
	if err != nil {
		return DeregisterResponse{}, err
	}

	switch hResp.StatusCode {
	case http.StatusOK:
		return resp, nil
	default:
		return DeregisterResponse{}, fmt.Errorf("%w: expected %d Created, got %d", api.ErrUnexpectedStatusCode, http.StatusOK, hResp.StatusCode)
	}
}

func (c *Client) doCall(ctx context.Context, path string, body any, rec any) (*http.Response, error) {
	bBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", api.ErrFailedToEncodeRequest, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(bBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", api.ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(AgentNameHeader, c.agentName)
	req.Header.Set(AgentIDHeader, c.agentID)

	resp, err := c.cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", api.ErrFailedToSendRequest, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		err = json.NewDecoder(resp.Body).Decode(rec)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", api.ErrFailedToDecodeResponse, err)
		}
	}
	return resp, nil
}
