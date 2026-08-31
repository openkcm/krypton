package interceptor

func AllowedURIs(a *Authenticator) map[string]struct{} {
	return a.allowedURIs
}
