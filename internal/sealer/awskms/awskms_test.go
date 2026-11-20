package awskms_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/sealer/awskms"
)

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *awskms.Config
		wantErr error
	}{
		{name: "valid", config: &awskms.Config{Region: "eu-central-1"}},
		{name: "nil config", config: nil, wantErr: awskms.ErrRegionMissing},
		{name: "region missing", config: &awskms.Config{}, wantErr: awskms.ErrRegionMissing},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.config.ValidateSealerConfig(), tt.wantErr)
		})
	}
}

func TestAuthValidation(t *testing.T) {
	static := func() *awskms.StaticCredentials {
		return &awskms.StaticCredentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret"}
	}

	tests := []struct {
		name    string
		auth    *awskms.Auth
		wantErr error
	}{
		{
			name:    "role missing",
			auth:    &awskms.Auth{Static: static()},
			wantErr: awskms.ErrRoleARNMissing,
		},
		{
			name: "static with role",
			auth: &awskms.Auth{RoleARN: "arn:aws:iam::111122223333:role/krypton", Static: static()},
		},
		{
			name: "static with role and external ID",
			auth: &awskms.Auth{RoleARN: "arn:aws:iam::111122223333:role/krypton", ExternalID: "ext", Static: static()},
		},
		{name: "nil auth", auth: nil, wantErr: awskms.ErrStaticCredentialsMissing},
		{name: "static missing", auth: &awskms.Auth{}, wantErr: awskms.ErrStaticCredentialsMissing},
		{
			name:    "access key ID missing",
			auth:    &awskms.Auth{Static: &awskms.StaticCredentials{SecretAccessKey: "secret"}},
			wantErr: awskms.ErrAccessKeyIDMissing,
		},
		{
			name:    "secret access key missing",
			auth:    &awskms.Auth{Static: &awskms.StaticCredentials{AccessKeyID: "AKIAEXAMPLE"}},
			wantErr: awskms.ErrSecretAccessKeyMissing,
		},
		{
			name:    "external ID without role",
			auth:    &awskms.Auth{ExternalID: "ext", Static: static()},
			wantErr: awskms.ErrRoleARNMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.auth.ValidateSealerAuth(), tt.wantErr)
		})
	}
}
