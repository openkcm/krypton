package sealers

import "context"

type SealerService struct {
	UnimplementedServiceServer
}

var _ ServiceServer = (*SealerService)(nil)

// Seal implements [ServiceServer].
func (s *SealerService) Seal(context.Context, *SealRequest) (*SealResponse, error) {
	panic("unimplemented")
}

// Unseal implements [ServiceServer].
func (s *SealerService) Unseal(context.Context, *UnsealRequest) (*UnsealResponse, error) {
	panic("unimplemented")
}
