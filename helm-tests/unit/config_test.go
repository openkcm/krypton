//go:build helmtests

package unit_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
)

// loadConfig writes config.yaml to a directory and loads it the way the root node does at
// startup (cmd/root/main.go): config.LoadRootConfig, which parses and validates it.
func loadConfig(t *testing.T, configYAML string) (*config.RootConfig, error) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")

	err := os.WriteFile(path, []byte(configYAML), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	return config.LoadRootConfig(path)
}

// unreadKeys returns the keys of configYAML that the root node does not read. The root node
// ignores unknown keys, so a misspelled key would go unnoticed: this writes the loaded
// configuration back as YAML and returns the keys of configYAML that are missing there. Keys
// with empty values are not checked, because the written configuration omits empty optional
// values.
func unreadKeys(t *testing.T, configYAML string, cfg *config.RootConfig) []string {
	t.Helper()

	var in map[string]any

	err := yaml.Unmarshal([]byte(configYAML), &in)
	if err != nil {
		t.Fatal(err)
	}

	var read map[string]any

	err = yaml.Unmarshal(must(yaml.Marshal(cfg))(t), &read)
	if err != nil {
		t.Fatal(err)
	}

	// Parts that are not written back with the rest: the type-specific part of auth, and the
	// secret of each static secret sealer.
	if cfg.Auth != nil {
		auth, _ := read["auth"].(map[string]any)
		auth["config"] = asMap(t, cfg.Auth.Config)
	}

	addSealerSecrets(t, read, cfg.KeyBindings)

	segments, _ := dig(read, "topology", "segments").([]any)
	for i, segment := range cfg.Topology.Segments {
		if i < len(segments) {
			segmentMap, _ := segments[i].(map[string]any)
			addSealerSecrets(t, segmentMap, segment.KeyBindings)
		}
	}

	var unread []string

	compareKeys("", in, read, &unread)
	slices.Sort(unread)

	return unread
}

// addSealerSecrets adds the secret of each static secret sealer of bindings to the written
// configuration parent, which has the key_bindings.
func addSealerSecrets(t *testing.T, parent map[string]any, bindings map[string]spec.KeyBinding) {
	t.Helper()

	for kind, binding := range bindings {
		if binding.SealerSpec == nil {
			continue
		}

		sealerConfig, ok := binding.SealerSpec.Config.(*staticsecret.Config)
		if !ok {
			continue
		}

		written, _ := dig(parent, "key_bindings", kind, "sealer", "config").(map[string]any)
		if written != nil {
			written["secret"] = asMap(t, &sealerConfig.Secret)
		}
	}
}

// asMap writes value as YAML and reads it back as a map.
func asMap(t *testing.T, value any) map[string]any {
	t.Helper()

	var result map[string]any

	err := yaml.Unmarshal(must(yaml.Marshal(value))(t), &result)
	if err != nil {
		t.Fatal(err)
	}

	return result
}

// dig returns the value at the keys of nested maps, or nil.
func dig(value any, keys ...string) any {
	for _, key := range keys {
		m, ok := value.(map[string]any)
		if !ok {
			return nil
		}

		value = m[key]
	}

	return value
}

// compareKeys adds to unread the paths of the non-empty values of in that read lacks.
func compareKeys(path string, in, read any, unread *[]string) {
	switch in := in.(type) {
	case map[string]any:
		readMap, _ := read.(map[string]any)
		for key, value := range in {
			if isEmpty(value) {
				continue
			}

			keyPath := key
			if path != "" {
				keyPath = path + "." + key
			}

			readValue, found := readMap[key]
			if !found {
				*unread = append(*unread, keyPath)
				continue
			}

			compareKeys(keyPath, value, readValue, unread)
		}
	case []any:
		readList, _ := read.([]any)
		for i, value := range in {
			if i < len(readList) {
				compareKeys(fmt.Sprintf("%s[%d]", path, i), value, readList[i], unread)
			}
		}
	}
}

func isEmpty(value any) bool {
	if value == nil {
		return true
	}

	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	default:
		return false
	}
}

// loadValues renders the chart with the arguments and loads the configuration the way the
// root node does at startup. It fails the test if the root node does not load it, or does not
// read all of it.
func loadValues(t *testing.T, args ...string) *config.RootConfig {
	t.Helper()

	configYAML := renderConfigYAML(t, args...)

	cfg, err := loadConfig(t, configYAML)
	if err != nil {
		t.Fatalf("the root node does not load the configuration: %v\n%s", err, configYAML)
	}

	if unread := unreadKeys(t, configYAML, cfg); len(unread) > 0 {
		t.Fatalf("keys that the root node does not read: %v\n%s", unread, configYAML)
	}

	return cfg
}

func TestConfigDefaults(t *testing.T) {
	cfg := loadValues(t)

	if cfg.Name != "root" || cfg.Role != config.RootRole {
		t.Errorf("name %q, role %q; want root, root", cfg.Name, cfg.Role)
	}

	if cfg.Auth != nil || cfg.KMIP != nil {
		t.Errorf("auth and kmip are set by default: %+v, %+v", cfg.Auth, cfg.KMIP)
	}

	// The agents reach the root at its own entry of connections: the chart's Service.
	root, err := cfg.Connections.ByNames(cfg.Name)
	if err != nil {
		t.Fatal(err)
	}

	if url := root[0].Address.URL; url != "krypton-root:8080" {
		t.Errorf("address of the root: %q, want the Service krypton-root:8080", url)
	}

	if len(cfg.KeyBindings) != 3 || len(cfg.Topology.Segments) != 0 {
		t.Errorf("want the demo hierarchy K0 to K2 without agents, got %d key bindings, %d segments",
			len(cfg.KeyBindings), len(cfg.Topology.Segments))
	}
}

// TestConfigPassThrough checks that everything under config except isImmutable reaches
// config.yaml, and that the unread-keys check of these tests finds keys that the root node
// ignores.
func TestConfigPassThrough(t *testing.T) {
	cm := object[configMap](t, render(t, "--set", "config.isImmutable=true", "--set", "config.futureSetting=on"),
		"ConfigMap")

	if !cm.Immutable {
		t.Error("config.isImmutable does not make the ConfigMap immutable")
	}

	configYAML := cm.Data["config.yaml"]
	if strings.Contains(configYAML, "isImmutable") {
		t.Errorf("config.yaml contains the chart setting isImmutable:\n%s", configYAML)
	}

	cfg := must(loadConfig(t, configYAML))(t)
	if unread := unreadKeys(t, configYAML, cfg); !slices.Equal(unread, []string{"futureSetting"}) {
		t.Errorf("unread keys: %v, want [futureSetting]", unread)
	}
}

// TestConfigMistakes checks that the tests and the release notes catch the mistakes that the
// root node would not report clearly.
func TestConfigMistakes(t *testing.T) {
	t.Run("misspelled key is ignored by the root node", func(t *testing.T) {
		configYAML := renderConfigYAML(t, "--set", "config.selector_label.region=eu10")

		cfg := must(loadConfig(t, configYAML))(t)
		if unread := unreadKeys(t, configYAML, cfg); !slices.Equal(unread, []string{"selector_label"}) {
			t.Errorf("unread keys: %v, want [selector_label]", unread)
		}
	})

	t.Run("KMIP TLS file names of Krypton v0.1.0", func(t *testing.T) {
		values := writeValues(t, `config:
  kmip:
    bind_addr: 0.0.0.0
    port: 5696
    tls:
      server_cert: /etc/krypton/kmip/tls.crt
      server_key: /etc/krypton/kmip/tls.key
      client_ca: /etc/krypton/kmip/ca.crt
`)

		_, err := loadConfig(t, renderConfigYAML(t, "-f", values))
		if err == nil || !strings.Contains(err.Error(), "kmip") {
			t.Errorf("want a kmip error for the v0.1.0 file names, got %v", err)
		}
	})

	t.Run("no connection for the root", func(t *testing.T) {
		_, err := loadConfig(t, renderConfigYAML(t, "--set", "config.connections=null"))
		if err == nil || !strings.Contains(err.Error(), `no connection config for root "root"`) {
			t.Errorf("want the missing root connection error, got %v", err)
		}
	})
}

// exampleValues returns a values file with a configuration made of the commented examples of
// values.yaml: a file vault, label requirements, an agent segment with its connection, mutual
// TLS and the KMIP server.
func exampleValues(t *testing.T) string {
	t.Helper()

	return "config:\n" +
		"  segment: { start_kind: K0, end_kind: K1 }\n" +
		"  key_bindings:\n" +
		"    K2: null\n" +
		indent(valuesComment(t, "on a persistent volume, or `openbao`:"), "    ") +
		"  hierarchy:\n" +
		"    name: example\n" +
		"    key_specs:\n" +
		"      - { kind: K0, role: root, algorithm: AES256, labels_spec: { allow_user_labels: true } }\n" +
		"      - { kind: K1, role: kek, algorithm: AES256, labels_spec: { allow_user_labels: true } }\n" +
		"      - { kind: K2, role: tek, algorithm: AES256, labels_spec: { allow_user_labels: true } }\n" +
		"      - kind: K3\n" +
		"        role: dek\n" +
		"        algorithm: AES256\n" +
		indent(valuesComment(t, "the labels its keys may or must have:"), "        ") +
		"  topology:\n" +
		indent(valuesComment(t, "and K3 (`dek`) in `hierarchy`:"), "    ") +
		"  connections:\n" +
		"    - { name: root, address: { type: grpc, url: krypton-root:8080 } }\n" +
		indent(valuesComment(t, "works for agents in the same namespace."), "    ") +
		"  auth:\n" +
		indent(valuesComment(t, "there for their format):"), "    ") +
		"  kmip:\n" +
		indent(valuesComment(t, "`ports` and `service.ports`:"), "    ")
}

// TestConfigExamples loads the configuration made of the commented examples of values.yaml.
func TestConfigExamples(t *testing.T) {
	cfg := loadValues(t, "-f", writeValues(t, exampleValues(t)))

	if len(cfg.Topology.Segments) != 1 || cfg.Auth == nil || cfg.KMIP == nil {
		t.Fatalf("the examples are not all in the configuration: %+v", cfg)
	}

	if _, err := cfg.AgentIdentities(cfg.Topology.Segments[0].Name); err != nil {
		t.Errorf("the agent of the example has no identities: %v", err)
	}
}

// readmeValues writes the example values file of the chart's README to a file and returns
// its path.
func readmeValues(t *testing.T) string {
	t.Helper()

	readme, err := os.ReadFile(chartPath + "/README.md")
	if err != nil {
		t.Fatal(err)
	}

	_, rest, found := strings.Cut(string(readme), "Create a values file")
	if found {
		_, rest, found = strings.Cut(rest, "```yaml\n")
	}

	example, _, closed := strings.Cut(rest, "```")
	if !found || !closed {
		t.Fatal("README.md has no complete values file example")
	}

	return writeValues(t, example)
}

// TestReadmeValues installs the chart with the values file of the README: the root node loads
// the configuration, its file vaults are on the writable volume, and the release notes only
// warn about the development vaults.
func TestReadmeValues(t *testing.T) {
	values := readmeValues(t)
	cfg := loadValues(t, "-f", values)

	_, c := rootContainer(t, "-f", values)
	for _, kind := range []string{"K1", "K2"} {
		vault, ok := cfg.KeyBindings[kind].VaultSpec.Config.(*sqlitevault.FileConfig)
		if !ok || !strings.HasPrefix(vault.Path, c.VolumeMounts[len(c.VolumeMounts)-1].MountPath+"/") {
			t.Errorf("%s vault %+v is not a file on the volume of the README", kind, cfg.KeyBindings[kind].VaultSpec)
		}
	}

	notes := releaseNotes(t, "-f", values)
	if strings.Count(notes, "\n  - ") != 1 || !strings.Contains(notes, "Development vaults") {
		t.Errorf("want only the development vault warning:\n%s", notes)
	}
}

// TestVaultTypes loads the vault types that values.yaml documents.
func TestVaultTypes(t *testing.T) {
	for vaultType, vault := range map[string]string{
		"unsafe-sqlite-memory": "{ name: kek-vault, type: unsafe-sqlite-memory }",
		"unsafe-sqlite":        "{ name: kek-vault, type: unsafe-sqlite, config: { path: /var/lib/krypton/kek.db } }",
		"openbao":              "{ name: kek-vault, type: openbao, config: { address: https://openbao.openbao:8200 } }",
	} {
		t.Run(vaultType, func(t *testing.T) {
			cfg := loadValues(t, "-f", writeValues(t, "config:\n  key_bindings:\n    K1:\n      vault: "+vault+"\n"))

			if got := string(cfg.KeyBindings["K1"].VaultSpec.Type); got != vaultType {
				t.Errorf("vault type %q, want %q", got, vaultType)
			}
		})
	}
}
