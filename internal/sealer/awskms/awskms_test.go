package awskms_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/sealer/awskms"
)

const (
	testRoleARN         = "arn:aws:iam::111122223333:role/krypton"
	externalIDMinLength = 2
	externalIDMaxLength = 1224
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
			auth: &awskms.Auth{RoleARN: testRoleARN, Static: static()},
		},
		{
			name: "static with role and external ID",
			auth: &awskms.Auth{RoleARN: testRoleARN, ExternalID: "ext", Static: static()},
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
		{
			name: "external ID at min length",
			auth: &awskms.Auth{RoleARN: testRoleARN, ExternalID: strings.Repeat("a", externalIDMinLength), Static: static()},
		},
		{
			name: "external ID at max length",
			auth: &awskms.Auth{RoleARN: testRoleARN, ExternalID: strings.Repeat("a", externalIDMaxLength), Static: static()},
		},
		{
			name: "external ID with all allowed characters",
			auth: &awskms.Auth{RoleARN: testRoleARN, ExternalID: "Ab1_+=,.@:/-", Static: static()},
		},
		{
			name: "external ID too short",
			auth: &awskms.Auth{
				RoleARN:    testRoleARN,
				ExternalID: strings.Repeat("a", externalIDMinLength-1),
				Static:     static(),
			},
			wantErr: awskms.ErrExternalIDInvalid,
		},
		{
			name: "external ID too long",
			auth: &awskms.Auth{
				RoleARN:    testRoleARN,
				ExternalID: strings.Repeat("a", externalIDMaxLength+1),
				Static:     static(),
			},
			wantErr: awskms.ErrExternalIDInvalid,
		},
		{
			name:    "external ID with space",
			auth:    &awskms.Auth{RoleARN: testRoleARN, ExternalID: "ext id", Static: static()},
			wantErr: awskms.ErrExternalIDInvalid,
		},
		{
			name:    "external ID with invalid character",
			auth:    &awskms.Auth{RoleARN: testRoleARN, ExternalID: "ext#id", Static: static()},
			wantErr: awskms.ErrExternalIDInvalid,
		},
		{
			name:    "external ID with non-ASCII letter",
			auth:    &awskms.Auth{RoleARN: testRoleARN, ExternalID: "extä", Static: static()},
			wantErr: awskms.ErrExternalIDInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.auth.ValidateSealerAuth(), tt.wantErr)
		})
	}
}

func TestEndpointValidation(t *testing.T) {
	tests := []struct {
		name     string
		endpoint *awskms.Endpoint
		wantErr  error
	}{
		{name: "nil endpoint", endpoint: nil},
		{name: "kms URL", endpoint: &awskms.Endpoint{KMSURL: "https://kms.internal:443"}},
		{
			name:     "kms and sts URLs with CA",
			endpoint: &awskms.Endpoint{KMSURL: "https://kms.internal", STSURL: "https://sts.internal", CAPath: "/ca.pem"},
		},
		{name: "CA only", endpoint: &awskms.Endpoint{CAPath: "/ca.pem"}},
		{
			name:     "plain http",
			endpoint: &awskms.Endpoint{KMSURL: "http://kms.internal"},
			wantErr:  awskms.ErrEndpointURLInvalid,
		},
		{
			name:     "host without scheme",
			endpoint: &awskms.Endpoint{KMSURL: "kms.internal"},
			wantErr:  awskms.ErrEndpointURLInvalid,
		},
		{
			name:     "invalid sts URL",
			endpoint: &awskms.Endpoint{KMSURL: "https://kms.internal", STSURL: "https://"},
			wantErr:  awskms.ErrEndpointURLInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.endpoint.Validate(), tt.wantErr)
		})
	}
}
