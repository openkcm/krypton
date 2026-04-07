package krhttp_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/krhttp"
)

type SuccessResp struct {
	Message string `json:"message"`
}

type ErrorResp struct {
	Message string `json:"message"`
}

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
		defer srv.Close()

		client := krhttp.NewClient(func(c *http.Client) {
			c.Timeout = 1 * time.Second // Set a very short timeout to trigger the timeout error
		})
		assert.NotNil(t, client)

		// when
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		err := krhttp.Do(client, req, krhttp.NewResponse[any, any](nil, nil))

		// then
		assert.Error(t, err, "Expected timeout error")
		assert.Equal(t, int32(1), actServerCall.Load(), "Expected server to be called once")
	})

	t.Run("should parse response correctly", func(t *testing.T) {
		tests := []struct {
			name          string
			expStatusCode int
			expMessage    string
			success       SuccessResp
			error         ErrorResp
			getMessage    func(resp *krhttp.Response[SuccessResp, ErrorResp]) string
		}{
			{
				name:          "error response",
				expStatusCode: http.StatusBadRequest,
				expMessage:    "bad request",
				success:       SuccessResp{},
				error:         ErrorResp{},
				getMessage: func(resp *krhttp.Response[SuccessResp, ErrorResp]) string {
					return resp.Error().Message
				},
			},
			{
				name:          "success response",
				expStatusCode: http.StatusOK,
				expMessage:    "success",
				success:       SuccessResp{},
				error:         ErrorResp{},
				getMessage: func(resp *krhttp.Response[SuccessResp, ErrorResp]) string {
					return resp.Success().Message
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// given
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.expStatusCode)

					message := fmt.Sprintf(`{"message":"%s"}`, tt.expMessage)
					_, err := w.Write([]byte(message))
					assert.NoError(t, err)
				}))
				defer srv.Close()

				client := krhttp.NewClient()
				assert.NotNil(t, client)

				// when
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
				resp := krhttp.NewResponse(&tt.success, &tt.error)
				err := krhttp.Do(client, req, resp)

				// then
				assert.NoError(t, err)
				assert.Equal(t, tt.expStatusCode, resp.Code())
				assert.Equal(t, tt.expMessage, tt.getMessage(resp))
			})
		}
	})

	t.Run("should return error when response body is not valid json", func(t *testing.T) {
		tests := []struct {
			name          string
			success       any
			error         any
			expStatusCode int
		}{
			{
				name:          "success response with invalid json",
				success:       SuccessResp{},
				error:         nil,
				expStatusCode: http.StatusOK,
			},
			{
				name:          "error response with invalid json",
				success:       nil,
				error:         ErrorResp{},
				expStatusCode: http.StatusBadRequest,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// given
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.expStatusCode)
					_, err := w.Write([]byte("invalid json"))
					assert.NoError(t, err)
				}))
				defer srv.Close()

				client := krhttp.NewClient()
				assert.NotNil(t, client)

				// when
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
				resp := krhttp.NewResponse(&tt.success, &tt.error)
				err := krhttp.Do(client, req, resp)

				// then
				assert.ErrorIs(t, err, krhttp.ErrFailedToDecodeResponse)
				assert.Equal(t, tt.expStatusCode, resp.Code())
			})
		}
	})

	t.Run("should not return decode error when response target is nil", func(t *testing.T) {
		tests := []struct {
			name          string
			expStatusCode int
		}{
			{
				name:          "error response is nil and status code is StatusBadRequest",
				expStatusCode: http.StatusBadRequest,
			},
			{
				name:          "success response is nil and status code is StatusOK",
				expStatusCode: http.StatusOK,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// given
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(tt.expStatusCode)
				}))
				defer srv.Close()

				client := krhttp.NewClient()
				assert.NotNil(t, client)

				// when
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
				resp := krhttp.NewResponse[any, any](nil, nil)
				err := krhttp.Do(client, req, resp)

				// then
				assert.NoError(t, err)
				assert.Equal(t, tt.expStatusCode, resp.Code())
				assert.Nil(t, resp.Success())
				assert.Nil(t, resp.Error())
			})
		}
	})
}
