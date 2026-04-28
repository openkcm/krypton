package spec

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// KryptonIDScheme is the URI scheme for krypton identities.
const KryptonIDScheme = "kryptonid"

var (
	// ErrInvalidScheme is returned when parsing a URI with wrong scheme.
	ErrInvalidScheme = errors.New("invalid scheme: must be 'kryptonid'")
	// ErrEmptyTrustDomain is returned when trust domain is empty.
	ErrEmptyTrustDomain = errors.New("trust domain cannot be empty")
	// ErrInvalidIdentityRole is returned when the role is not 'root' or 'agent'.
	ErrInvalidIdentityRole = errors.New("invalid identity role: must be 'root' or 'agent'")
	// ErrEmptyAgentName is returned when agent name is empty.
	ErrEmptyAgentName = errors.New("agent name cannot be empty")
	// ErrNoKryptonID is returned when certificate has no krypton identity.
	ErrNoKryptonID = errors.New("no krypton identity in certificate")
)

// KryptonID represents a krypton identity.
type KryptonID struct {
	TrustDomain string    `json:"trust_domain"`
	Role        AgentRole `json:"role"`
	Name        string    `json:"name"`
}

// URI returns the URI representation.
// Format: kryptonid://<trust-domain>/<role>/<name>
func (k KryptonID) URI() string {
	if k.Role == RootRole {
		return fmt.Sprintf("%s://%s/%s", KryptonIDScheme, k.TrustDomain, RootRole)
	}
	return fmt.Sprintf("%s://%s/%s/%s", KryptonIDScheme, k.TrustDomain, DefaultRole, k.Name)
}

// PrincipalName returns the identifier used for authorization.
// Returns "root" for root, agent name for agents.
func (k KryptonID) PrincipalName() string {
	if k.Role == RootRole {
		return string(RootRole)
	}
	return k.Name
}

// IsRoot returns true if this is the root identity.
func (k KryptonID) IsRoot() bool {
	return k.Role == RootRole
}

// RootID creates a root KryptonID for the given trust domain.
func RootID(trustDomain string) KryptonID {
	return KryptonID{
		TrustDomain: trustDomain,
		Role:        RootRole,
	}
}

// AgentID creates an agent KryptonID.
func AgentID(trustDomain, name string) KryptonID {
	return KryptonID{
		TrustDomain: trustDomain,
		Role:        DefaultRole,
		Name:        name,
	}
}

// ParseKryptonID parses a kryptonid:// URI into a KryptonID.
func ParseKryptonID(uri string) (KryptonID, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return KryptonID{}, fmt.Errorf("invalid URI: %w", err)
	}

	if u.Scheme != KryptonIDScheme {
		return KryptonID{}, ErrInvalidScheme
	}

	trustDomain := u.Host
	if trustDomain == "" {
		return KryptonID{}, ErrEmptyTrustDomain
	}

	path := strings.TrimPrefix(u.Path, "/")
	parts := strings.SplitN(path, "/", 2)

	switch AgentRole(parts[0]) {
	case RootRole:
		return KryptonID{
			TrustDomain: trustDomain,
			Role:        RootRole,
		}, nil
	case DefaultRole:
		if len(parts) < 2 || parts[1] == "" {
			return KryptonID{}, ErrEmptyAgentName
		}
		return KryptonID{
			TrustDomain: trustDomain,
			Role:        DefaultRole,
			Name:        parts[1],
		}, nil
	default:
		return KryptonID{}, ErrInvalidIdentityRole
	}
}

// KryptonIDFromCertificate extracts KryptonID from an X.509 certificate's URI SAN.
func KryptonIDFromCertificate(cert *x509.Certificate) (KryptonID, error) {
	for _, uri := range cert.URIs {
		if uri.Scheme == KryptonIDScheme {
			return ParseKryptonID(uri.String())
		}
	}
	return KryptonID{}, ErrNoKryptonID
}
