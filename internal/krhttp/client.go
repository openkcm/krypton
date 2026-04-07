package krhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPClientOpts is a functional option for configuring the underlying http.Client.
type HTTPClientOpts func(*http.Client)

// Client is a wrapper around http.Client with connection pooling and timeout defaults.
type Client struct {
	cli *http.Client
}

// ErrFailedToDecodeResponse is returned when the response body cannot be decoded as JSON.
var ErrFailedToDecodeResponse = errors.New("failed to decode response")

// NewClient creates a Client with default transport settings (20 max connections, 30s idle timeout,
// 10s request timeout). Use HTTPClientOpts to override defaults.
func NewClient(opts ...HTTPClientOpts) *Client {
	cli := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        20,
			MaxConnsPerHost:     20,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     30 * time.Second,
		},
		Timeout: 10 * time.Second,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(cli)
		}
	}

	return &Client{cli: cli}
}

// Do executes the request and decodes the JSON response. Status 2xx responses are decoded into
// the success target; all others into the error target. If the target is nil, decoding is skipped.
func Do[S any, E any](c *Client, req *http.Request, resp *Response[S, E]) error {
	hRes, err := c.cli.Do(req)
	if err != nil {
		return err
	}
	defer hRes.Body.Close()

	resp.code = hRes.StatusCode
	if hRes.StatusCode >= 200 && hRes.StatusCode < 300 {
		if resp.success == nil {
			return nil
		}
		return decodeResponse(hRes.Body, resp.success)
	}

	if resp.error == nil {
		return nil
	}
	return decodeResponse(hRes.Body, resp.error)
}

func decodeResponse(body io.Reader, to any) error {
	err := json.NewDecoder(body).Decode(to)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFailedToDecodeResponse, err)
	}
	return nil
}
