package integration

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/authn"
)

func TestLogin(t *testing.T) {
	tests := []struct {
		name        string
		setupToken  bool
		expContains string
	}{
		{
			name:        "login without existing token",
			setupToken:  false,
			expContains: "Login successful.",
		},
		{
			name:        "login with existing token",
			setupToken:  true,
			expContains: "Already logged in.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpHome := t.TempDir()

			if tt.setupToken {
				createTestToken(t, tmpHome)
			}

			cmd := newCLICommand(t.Context(), tmpHome, "login", "no-auth")

			output, err := cmd.CombinedOutput()
			assert.NoError(t, err)
			assert.Contains(t, string(output), tt.expContains)
		})
	}
}

func TestLogin_CreateTokenFile(t *testing.T) {
	tmpHome := t.TempDir()

	cmd := newCLICommand(t.Context(), tmpHome, "login", "no-auth")

	_, err := cmd.CombinedOutput()
	assert.NoError(t, err)

	tokenPath := filepath.Join(tmpHome, ".krypton", "token.json")
	_, err = os.Stat(tokenPath)
	assert.NoError(t, err, "token file should exist after login")

	data, err := os.ReadFile(tokenPath)
	assert.NoError(t, err)

	var token authn.Token
	err = json.Unmarshal(data, &token)
	assert.NoError(t, err)
}

func TestLogin_Help(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		expContains string
	}{
		{
			name:        "login help with long flag",
			args:        []string{"login", "no-auth", "--help"},
			expContains: "Authenticate with the Krypton server",
		},
		{
			name:        "login help with short flag",
			args:        []string{"login", "no-auth", "-h"},
			expContains: "Authenticate with the Krypton server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newCLICommand(t.Context(), t.TempDir(), tt.args...)
			output, err := cmd.CombinedOutput()

			assert.NoError(t, err)
			assert.Contains(t, string(output), tt.expContains)
		})
	}
}

func createTestToken(t *testing.T, homeDir string) {
	t.Helper()

	kryptonDir := filepath.Join(homeDir, ".krypton")
	err := os.MkdirAll(kryptonDir, 0700)
	assert.NoError(t, err)

	token := authn.Token{
		Type:      authn.NoAuth,
		Value:     []byte("test-token-value"),
		ExpiredAt: 9999999999,
		Attributes: map[string]any{
			"test": true,
		},
	}

	data, err := json.Marshal(token)
	assert.NoError(t, err)

	tokenPath := filepath.Join(kryptonDir, "token.json")
	err = os.WriteFile(tokenPath, data, 0600)
	assert.NoError(t, err)
}
