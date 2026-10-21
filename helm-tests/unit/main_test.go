//go:build helmtests

// Package unit_test renders the Krypton root node Helm chart (charts/root) with
// `helm template` and checks the output; it loads the rendered configuration with the root
// node's own code. It needs the helm command, but no cluster. Run from the repository root:
//
//	make helm-test
package unit_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	chartPath   = "../../charts/root"
	releaseName = "krypton"
	namespace   = "services"
)

// TestMain renders the chart into the namespace of the tests, whatever the current
// kubeconfig context is.
func TestMain(m *testing.M) {
	err := os.Setenv("HELM_NAMESPACE", namespace)
	if err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}

// runHelm runs helm with the arguments and returns its output.
func runHelm(t *testing.T, args ...string) (string, error) {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), "helm", args...) //nolint:gosec // arguments come from the tests

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", errors.New(strings.TrimSpace(stderr.String()))
	}

	return stdout.String(), nil
}

// render runs `helm template` with the given --set/-f arguments and returns the output.
func render(t *testing.T, args ...string) string {
	t.Helper()

	out, err := runHelm(t, append([]string{"template", releaseName, chartPath}, args...)...)
	if err != nil {
		t.Fatalf("helm template failed: %v", err)
	}

	return out
}

// renderError runs `helm template` with arguments that must fail and returns the error.
func renderError(t *testing.T, args ...string) error {
	t.Helper()

	_, err := runHelm(t, append([]string{"template", releaseName, chartPath}, args...)...)
	if err == nil {
		t.Fatalf("helm template succeeded with %v", args)
	}

	return err
}

// objects decodes every rendered document of the given kind into a value of type T and
// returns them.
func objects[T any](t *testing.T, output, kind string) []T {
	t.Helper()

	var result []T

	dec := yaml.NewDecoder(strings.NewReader(output))

	for {
		var doc yaml.Node

		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatalf("decode the rendered chart: %v", err)
		}

		var header struct {
			Kind string `yaml:"kind"`
		}

		err = doc.Decode(&header)
		if err != nil {
			t.Fatalf("decode the kind: %v", err)
		}

		if header.Kind != kind {
			continue
		}

		var obj T

		err = doc.Decode(&obj)
		if err != nil {
			t.Fatalf("decode %s: %v", kind, err)
		}

		result = append(result, obj)
	}

	return result
}

// object decodes the only rendered document of the given kind.
func object[T any](t *testing.T, output, kind string) T {
	t.Helper()

	objs := objects[T](t, output, kind)
	if len(objs) != 1 {
		t.Fatalf("want one %s in the rendered chart, got %d:\n%s", kind, len(objs), output)
	}

	return objs[0]
}

// configMap is the part of the configuration ConfigMap that the tests check.
type configMap struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Immutable bool              `yaml:"immutable"`
	Data      map[string]string `yaml:"data"`
}

// renderConfigYAML renders the chart and returns config.yaml of the configuration ConfigMap.
func renderConfigYAML(t *testing.T, args ...string) string {
	t.Helper()

	cm := object[configMap](t, render(t, args...), "ConfigMap")

	cfg, ok := cm.Data["config.yaml"]
	if !ok {
		t.Fatal("the ConfigMap has no config.yaml")
	}

	return cfg
}

// appVersion returns the chart's appVersion, the default image tag.
func appVersion(t *testing.T) string {
	t.Helper()

	chart, err := os.ReadFile(chartPath + "/Chart.yaml")
	if err != nil {
		t.Fatal(err)
	}

	var meta struct {
		AppVersion string `yaml:"appVersion"`
	}

	err = yaml.Unmarshal(chart, &meta)
	if err != nil || meta.AppVersion == "" {
		t.Fatalf("Chart.yaml has no appVersion: %v", err)
	}

	return meta.AppVersion
}

// writeValues writes a values file to the test's temporary directory and returns its path.
func writeValues(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "values.yaml")

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	return path
}

// valuesComment returns the commented example of values.yaml below the line that ends with
// marker: the following comment lines that are indented by at least three spaces after the
// comment sign, without the comment sign and these three spaces.
func valuesComment(t *testing.T, marker string) string {
	t.Helper()

	values, err := os.ReadFile(chartPath + "/values.yaml")
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(string(values), "\n")

	var example []string

	for i, line := range lines {
		if !strings.HasSuffix(line, marker) {
			continue
		}

		if example != nil {
			t.Fatalf("more than one line of values.yaml ends with %q", marker)
		}

		before, _, found := strings.Cut(line, "#")
		if !found {
			t.Fatalf("%q is not in a comment of values.yaml", marker)
		}

		example = []string{}

		for _, next := range lines[i+1:] {
			text, ok := strings.CutPrefix(next, before+"#   ")
			if !ok {
				break
			}

			example = append(example, text)
		}

		if len(example) == 0 {
			t.Fatalf("no example below %q in values.yaml", marker)
		}
	}

	if example == nil {
		t.Fatalf("no line of values.yaml ends with %q", marker)
	}

	return strings.Join(example, "\n") + "\n"
}

// indent prefixes every non-empty line of text with prefix.
func indent(text, prefix string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}

	return strings.Join(lines, "\n") + "\n"
}
