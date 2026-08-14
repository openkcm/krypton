package interceptor

func AllowedCNs(a *Authenticator) map[string]struct{} {
	return a.allowedCNs
}
