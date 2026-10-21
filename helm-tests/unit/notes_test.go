//go:build helmtests

package unit_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// releaseNotes renders templates/NOTES.txt with the arguments, without a cluster. `helm install
// --dry-run=client` needs a reachable cluster with Helm 3, and `helm template` does not render
// the notes, so the test renders a copy of the chart in which NOTES.txt is a named template that
// a test-only ConfigMap writes out. The notes get the same values and helpers as in an install.
func releaseNotes(t *testing.T, args ...string) string {
	t.Helper()

	chart := filepath.Join(t.TempDir(), filepath.Base(chartPath))

	err := os.CopyFS(chart, os.DirFS(chartPath))
	if err != nil {
		t.Fatal(err)
	}

	templates := filepath.Join(chart, "templates")

	notes, err := os.ReadFile(filepath.Join(templates, "NOTES.txt"))
	if err == nil {
		err = os.Remove(filepath.Join(templates, "NOTES.txt"))
	}

	if err != nil {
		t.Fatal(err)
	}

	for name, content := range map[string]string{
		"_notes_under_test.tpl": "{{- define \"notesUnderTest\" -}}\n" + string(notes) + "\n{{- end -}}\n",
		"notes-under-test.yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: notes-under-test\n" +
			"data:\n  notes: {{ include \"notesUnderTest\" . | toJson }}\n",
	} {
		err = os.WriteFile(filepath.Join(templates, name), []byte(content), 0o600)
		if err != nil {
			t.Fatal(err)
		}
	}

	out, err := runHelm(t, append([]string{"template", releaseName, chart,
		"--show-only", "templates/notes-under-test.yaml"}, args...)...)
	if err != nil {
		t.Fatalf("rendering the release notes failed: %v", err)
	}

	cm := object[configMap](t, out, "ConfigMap")
	if cm.Data["notes"] == "" {
		t.Fatalf("no release notes in the output:\n%s", out)
	}

	return cm.Data["notes"]
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
