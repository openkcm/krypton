//go:build helmtests

package unit_test

import (
	"strings"
	"testing"
)

// resource is the kind and name of a rendered resource.
type resource struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
}

// resources renders the chart as the release and returns its resources as "Kind/name".
func resources(t *testing.T, release string, args ...string) []string {
	t.Helper()

	output, err := runHelm(t, append([]string{"template", release, chartPath}, args...)...)
	if err != nil {
		t.Fatalf("helm template failed: %v", err)
	}

	var result []string

	for _, kind := range []string{
		"ConfigMap", "Deployment", "HorizontalPodAutoscaler", "NetworkPolicy",
		"PodDisruptionBudget", "Service", "ServiceAccount",
	} {
		for _, r := range objects[resource](t, output, kind) {
			if r.Metadata.Namespace != namespace {
				t.Errorf("%s/%s is in namespace %q, want %q", r.Kind, r.Metadata.Name, r.Metadata.Namespace, namespace)
			}

			result = append(result, r.Kind+"/"+r.Metadata.Name)
		}
	}

	return result
}

func TestChartResources(t *testing.T) {
	tests := []struct {
		name    string
		release string
		args    []string
		want    string
	}{
		{
			name: "defaults",
			want: "ConfigMap/krypton-root-config Deployment/krypton-root Service/krypton-root ServiceAccount/krypton-root",
		},
		{
			name: "all optional resources",
			args: []string{
				"--set", "hpa.enabled=true", "--set", "networkPolicy.enabled=true",
				"--set", "pod.disruptionBudget.enabled=true",
			},
			want: "ConfigMap/krypton-root-config Deployment/krypton-root HorizontalPodAutoscaler/krypton-root " +
				"NetworkPolicy/krypton-root PodDisruptionBudget/krypton-root Service/krypton-root ServiceAccount/krypton-root",
		},
		{
			name: "no ServiceAccount",
			args: []string{"--set", "serviceAccount.create=false"},
			want: "ConfigMap/krypton-root-config Deployment/krypton-root Service/krypton-root",
		},
		{
			name:    "release name containing the chart name",
			release: "eu10-krypton-root",
			want: "ConfigMap/eu10-krypton-root-config Deployment/eu10-krypton-root Service/eu10-krypton-root " +
				"ServiceAccount/eu10-krypton-root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release := tt.release
			if release == "" {
				release = releaseName
			}

			if got := strings.Join(resources(t, release, tt.args...), " "); got != tt.want {
				t.Errorf("resources:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

func TestDisruptionBudget(t *testing.T) {
	type pdb struct {
		Spec map[string]any `yaml:"spec"`
	}

	tests := []struct {
		args []string
		key  string
		want any
	}{
		{key: "maxUnavailable", want: 1},
		{args: []string{"--set", "pod.disruptionBudget.minAvailable=50%"}, key: "minAvailable", want: "50%"},
	}

	for _, tt := range tests {
		args := append([]string{"--set", "pod.disruptionBudget.enabled=true"}, tt.args...)
		spec := object[pdb](t, render(t, args...), "PodDisruptionBudget").Spec

		if spec[tt.key] != tt.want {
			t.Errorf("with %v: %s %v, want %v", tt.args, tt.key, spec[tt.key], tt.want)
		}
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "extraPorts of chart 0.0.1",
			args: []string{"--set", "extraPorts[0].name=kmip", "--set", "extraPorts[0].containerPort=5696"},
			want: "extraPorts was renamed to ports",
		},
		{
			name: "image.pullSecrets of chart 0.0.1",
			args: []string{"--set", "image.pullSecrets[0].name=registry-access"},
			want: "image.pullSecrets was renamed to imagePullSecrets",
		},
		{
			name: "autoscaler without target",
			args: []string{
				"--set", "hpa.enabled=true",
				"--set", "hpa.targetCPUUtilizationPercentage=null",
				"--set", "hpa.targetMemoryUtilizationPercentage=null",
			},
			want: "hpa.enabled requires",
		},
		{
			name: "disruption budget with both limits",
			args: []string{
				"--set", "pod.disruptionBudget.enabled=true",
				"--set", "pod.disruptionBudget.minAvailable=1",
				"--set", "pod.disruptionBudget.maxUnavailable=1",
			},
			want: "set either minAvailable or maxUnavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := renderError(t, tt.args...); !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q, want %q", err, tt.want)
			}
		})
	}
}
