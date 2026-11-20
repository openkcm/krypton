package awskms

import (
	"errors"

	"github.com/openkcm/krypton/internal/sealer"
)

const TypeAwsKms sealer.Type = "awskms"

var (
	ErrRegionMissing            = errors.New("region is missing")
	ErrStaticCredentialsMissing = errors.New("static credentials are missing")
	ErrAccessKeyIDMissing       = errors.New("access key ID is missing")
	ErrSecretAccessKeyMissing   = errors.New("secret access key is missing")
	ErrRoleARNMissing           = errors.New("role ARN is missing")
	ErrKeyARNMissing            = errors.New("provider key ARN is missing")
	ErrEncrypt                  = errors.New("aws kms encrypt failed")
	ErrDecrypt                  = errors.New("aws kms decrypt failed")
)

type Config struct {
	Region string `yaml:"region"`
}

var _ sealer.SealerConfig = (*Config)(nil)

func (c *Config) ValidateSealerConfig() error {
	if c == nil || c.Region == "" {
		return ErrRegionMissing
	}
	return nil
}

type Auth struct {
	RoleARN    string             `yaml:"role_arn,omitempty"`
	ExternalID string             `yaml:"external_id,omitempty"`
	Static     *StaticCredentials `yaml:"static,omitempty"`
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
	return nil
}
