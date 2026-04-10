package api

import "errors"

var (
	ErrBaseURLEmpty           = errors.New("base URL cannot be empty")
	ErrFailedToEncodeRequest  = errors.New("failed to encode request")
	ErrFailedToCreateRequest  = errors.New("failed to create request")
	ErrFailedToSendRequest    = errors.New("failed to send request")
	ErrUnexpectedStatusCode   = errors.New("unexpected status code")
	ErrFailedToDecodeResponse = errors.New("failed to decode response")
)
