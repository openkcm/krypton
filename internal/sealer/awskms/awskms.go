package awskms

import (
	"errors"
	"net/url"
	"regexp"

	"github.com/openkcm/krypton/internal/sealer"
)

const TypeAwsKms sealer.Type = "awskms"

// AWS STS limits for the ExternalId of AssumeRole.
const (
	externalIDMinLength = 2
	externalIDMaxLength = 1224
)

var externalIDPattern = regexp.MustCompile(`^[\w+=,.@:/-]+$`)

var (
	ErrRegionMissing            = errors.New("region is missing")
	ErrStaticCredentialsMissing = errors.New("static credentials are missing")
	ErrAccessKeyIDMissing       = errors.New("access key ID is missing")
	ErrSecretAccessKeyMissing   = errors.New("secret access key is missing")
	ErrRoleARNMissing           = errors.New("role ARN is missing")
	ErrExternalIDInvalid        = errors.New("external ID must be 2-1224 characters of letters, digits and _+=,.@:/-")
	ErrKeyARNMissing            = errors.New("provider key ARN is missing")
	ErrEncrypt                  = errors.New("aws kms encrypt failed")
	ErrDecrypt                  = errors.New("aws kms decrypt failed")
	ErrResultMissing            = errors.New("aws kms result missing from secure memory")
	ErrEndpointURLInvalid       = errors.New("endpoint URL must be an absolute https URL")
)

type Config struct {
	Region      string `yaml:"region"`
	KMSEndpoint string `yaml:"kms_endpoint,omitempty"`
	STSEndpoint string `yaml:"sts_endpoint,omitempty"`
}

var _ sealer.SealerConfig = (*Config)(nil)

func (c *Config) ValidateSealerConfig() error {
	if c == nil || c.Region == "" {
		return ErrRegionMissing
	}
	for _, raw := range []string{c.KMSEndpoint, c.STSEndpoint} {
		if raw != "" && !httpsURL(raw) {
			return ErrEndpointURLInvalid
		}
	}
	return nil
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

type Auth struct {
	RoleARN    string             `yaml:"role_arn"`
	ExternalID string             `yaml:"external_id"`
	Static     *StaticCredentials `yaml:"static"`
}

type StaticCredentials struct {
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
}

var _ sealer.SealerAuth = (*Auth)(nil)

func (a *Auth) ValidateSealerAuth() error {
	if a == nil || a.Static == nil {
		return ErrStaticCredentialsMissing
	}
	if a.Static.AccessKeyID == "" {
		return ErrAccessKeyIDMissing
	}
	if a.Static.SecretAccessKey == "" {
		return ErrSecretAccessKeyMissing
	}
	if a.RoleARN == "" {
		return ErrRoleARNMissing
	}
	if a.ExternalID != "" && !validExternalID(a.ExternalID) {
		return ErrExternalIDInvalid
	}
	return nil
}

func validExternalID(id string) bool {
	return len(id) >= externalIDMinLength && len(id) <= externalIDMaxLength && externalIDPattern.MatchString(id)
}
