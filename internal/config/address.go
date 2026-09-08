package config

import "fmt"

// AddressTypeGRPC represents gRPC transport.
const AddressTypeGRPC AddressType = "grpc"

// AddressType identifies the transport protocol for inter-service communication.
type AddressType string

// Address represents a network address for inter-service communication.
type Address struct {
	Type AddressType `yaml:"type"`
	URL  string      `yaml:"url"`
}

// Validate checks the Address for structural correctness.
func (a *Address) Validate() error {
	if a.Type != AddressTypeGRPC {
		return fmt.Errorf("%w: must be %q", ErrAddressTypeInvalid, AddressTypeGRPC)
	}
	if a.URL == "" {
		return ErrConfigAddressEmpty
	}
	return nil
}
