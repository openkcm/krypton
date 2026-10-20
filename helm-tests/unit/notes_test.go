//go:build helmtests

package unit_test

import (
	"strings"
	"testing"
)

// releaseNotes renders the release notes (templates/NOTES.txt) with the arguments.
func releaseNotes(t *testing.T, args ...string) string {
	t.Helper()

	out, err := runHelm(t, append([]string{"install", releaseName, chartPath, "--dry-run=client"}, args...)...)
	if err != nil {
		t.Fatalf("helm install --dry-run failed: %v", err)
	}

	_, notes, found := strings.Cut(out, "NOTES:\n")
	if !found {
		t.Fatalf("no release notes in:\n%s", out)
	}

	return notes
}

// Values with which the root node starts: its Secrets, a network policy and a file vault.
var startingValues = []string{
	"--set", "database.existingSecret=krypton-secret",
	"--set", "rootKey.existingSecret=krypton-secret",
	"--set", "networkPolicy.enabled=true",
}

func TestReleaseNotes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		// warnings that the notes must contain, by a part of their text.
		warnings []string
	}{
		{
			name: "defaults",
			warnings: []string{
				"DATABASE_URL is not set",
				"KRYPTON_ROOT_KEY is not set",
				"Development vaults in config.key_bindings: K1 (unsafe-sqlite-memory), K2 (unsafe-sqlite-memory)",
				"config.auth is not set and networkPolicy.enabled is false",
			},
		},
		{
			name:     "secrets and network policy",
			args:     startingValues,
			warnings: []string{"Development vaults"},
		},
		{
			name: "secrets from extraEnvs",
			args: []string{
				"--set", "extraEnvs[0].name=DATABASE_URL", "--set", "extraEnvs[0].value=postgres://db",
				"--set", "extraEnvs[1].name=KRYPTON_ROOT_KEY", "--set", "extraEnvs[1].value=key",
				"--set", "networkPolicy.enabled=true",
			},
			warnings: []string{"Development vaults"},
		},
		{
			name: "another sealer variable",
			args: append([]string{
				"--set", "config.key_bindings.K0.sealer.config.secret.config.name=ROOT_SEAL_KEY",
			}, startingValues...),
			warnings: []string{"Development vaults", "ROOT_SEAL_KEY is not set"},
		},
		{
			name:     "two pods with development vaults",
			args:     append([]string{"--set", "replicaCount=2"}, startingValues...),
			warnings: []string{"Development vaults", "More than one pod with unsafe-sqlite vaults"},
		},
		{
			name:     "rolling update with development vaults",
			args:     append([]string{"--set", "strategy.type=RollingUpdate"}, startingValues...),
			warnings: []string{"Development vaults", "strategy is not Recreate"},
		},
		{
			name: "no development vault",
			args: append([]string{
				"--set", "config.key_bindings.K1.vault.type=openbao",
				"--set", "config.key_bindings.K2.vault.type=openbao",
				"--set", "replicaCount=2",
			}, startingValues...),
		},
		{
			name:     "no connection for the root",
			args:     append([]string{"--set", "config.connections=null"}, startingValues...),
			warnings: []string{"Development vaults", `config.connections has no entry named "root"`},
		},
		{
			name: "KMIP server without port",
			args: append([]string{
				"--set", "config.kmip.bind_addr=0.0.0.0", "--set", "config.kmip.port=5696",
			}, startingValues...),
			warnings: []string{"Development vaults", "ports has no port named kmip"},
		},
		{
			name:     "service outside the cluster",
			args:     append([]string{"--set", "service.type=LoadBalancer"}, startingValues...),
			warnings: []string{"Development vaults", "service.type is LoadBalancer"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notes := releaseNotes(t, tt.args...)

			for _, want := range []string{
				"krypton-root.services.svc:8080",
				"kubectl --namespace services port-forward service/krypton-root 8080:grpc",
			} {
				if !strings.Contains(notes, want) {
					t.Errorf("the notes lack %q:\n%s", want, notes)
				}
			}

			_, warnings, _ := strings.Cut(notes, "WARNINGS:\n")
			warnings, _, _ = strings.Cut(warnings, "\n\n")

			lines := strings.Count(warnings, "\n  - ")
			if warnings != "" {
				lines++
			}

			if lines != len(tt.warnings) {
				t.Errorf("%d warnings, want %d:\n%s", lines, len(tt.warnings), warnings)
			}

			for _, want := range tt.warnings {
				if !strings.Contains(warnings, want) {
					t.Errorf("no warning %q:\n%s", want, warnings)
				}
			}
		})
	}
}
