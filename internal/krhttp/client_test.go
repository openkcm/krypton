package krhttp_test

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/krhttp"
)

func TestNewClient(t *testing.T) {
	t.Run("should create client for valid url and empty opts", func(t *testing.T) {
		// given when
		client := krhttp.NewClient()

		// then
		assert.NotNil(t, client)
	})
	t.Run("should create client for valid url and nil opts", func(t *testing.T) {
		// given when
		client := krhttp.NewClient(nil)

		// then
		assert.NotNil(t, client)
	})

	t.Run("should create client for valid url and custom opts", func(t *testing.T) {
		// This test ensures that the custom options are applied correctly to the HTTP client.
		// here we set a custom timeout and verify that it is applied to the client.

		// given
		var actServerCall atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actServerCall.Add(1)
			time.Sleep(10 * time.Second) // Simulate some processing time
		}))
		t.Cleanup(srv.Close)

		client := krhttp.NewClient(func(c *http.Client) {
			c.Timeout = 1 * time.Second // Set a very short timeout to trigger the timeout error
		})
		assert.NotNil(t, client)

		// when
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		_, err := client.Do(req)

		// then
		assert.Error(t, err, "Expected timeout error")
		assert.Equal(t, int32(1), actServerCall.Load(), "Expected server to be called once")
	})
}
