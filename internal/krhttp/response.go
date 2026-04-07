package krhttp

// Response holds a typed success and error payload along with the HTTP status code.
type Response[S any, E any] struct {
	success *S
	error   *E
	code    int
}

// NewResponse creates a Response. Pass non-nil pointers to enable JSON decoding for that direction, or nil to skip it.
func NewResponse[S any, E any](successResp *S, errorResp *E) *Response[S, E] {
	return &Response[S, E]{
		success: successResp,
		error:   errorResp,
	}
}

// Code returns the HTTP status code of the response.
func (r *Response[S, E]) Code() int {
	return r.code
}

// Success returns the decoded success payload, or nil if no success target was provided.
func (r *Response[S, E]) Success() *S {
	return r.success
}

// Error returns the decoded error payload, or nil if no error target was provided.
func (r *Response[S, E]) Error() *E {
	return r.error
}
