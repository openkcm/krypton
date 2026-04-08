package krhttp

import (
	"net/http"
	"time"
)

// HTTPClientOpts is a functional option for configuring the underlying http.Client.
type HTTPClientOpts func(*http.Client)

// Client is a wrapper around http.Client with connection pooling and timeout defaults.
type Client struct {
	cli *http.Client
}

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

// Do sends an HTTP request and returns an HTTP response.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.cli.Do(req)
}
