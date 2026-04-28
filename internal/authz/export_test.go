package authz

// Authorize exposes the unexported authorize method for testing.
func (a *AuthZ) Authorize(ctx Context) error {
	return a.authorize(ctx)
}
