//go:build helmtests

package unit_test

import (
	"maps"
	"slices"
	"testing"
)

// deployment is the part of the Deployment that the tests check.
type deployment struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Replicas *int `yaml:"replicas"`
		Strategy struct {
			Type string `yaml:"type"`
		} `yaml:"strategy"`
		Selector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"selector"`
		Template struct {
			Metadata struct {
				Annotations map[string]string `yaml:"annotations"`
				Labels      map[string]string `yaml:"labels"`
			} `yaml:"metadata"`
			Spec struct {
				ServiceAccountName           string `yaml:"serviceAccountName"`
				AutomountServiceAccountToken *bool  `yaml:"automountServiceAccountToken"`
				EnableServiceLinks           *bool  `yaml:"enableServiceLinks"`
				ImagePullSecrets             []struct {
					Name string `yaml:"name"`
				} `yaml:"imagePullSecrets"`
				SecurityContext struct {
					RunAsNonRoot   bool  `yaml:"runAsNonRoot"`
					RunAsUser      int64 `yaml:"runAsUser"`
					RunAsGroup     int64 `yaml:"runAsGroup"`
					FSGroup        int64 `yaml:"fsGroup"`
					SeccompProfile struct {
						Type string `yaml:"type"`
					} `yaml:"seccompProfile"`
				} `yaml:"securityContext"`
				Containers []container `yaml:"containers"`
				Volumes    []struct {
					Name      string `yaml:"name"`
					ConfigMap *struct {
						Name string `yaml:"name"`
					} `yaml:"configMap"`
					EmptyDir *struct {
						SizeLimit string `yaml:"sizeLimit"`
					} `yaml:"emptyDir"`
				} `yaml:"volumes"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type container struct {
	Name            string   `yaml:"name"`
	Image           string   `yaml:"image"`
	Command         []string `yaml:"command"`
	Args            []string `yaml:"args"`
	SecurityContext struct {
		AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
		ReadOnlyRootFilesystem   bool  `yaml:"readOnlyRootFilesystem"`
		Capabilities             struct {
			Drop []string `yaml:"drop"`
		} `yaml:"capabilities"`
	} `yaml:"securityContext"`
	Ports []struct {
		Name          string `yaml:"name"`
		ContainerPort int    `yaml:"containerPort"`
	} `yaml:"ports"`
	Env []struct {
		Name      string `yaml:"name"`
		Value     string `yaml:"value"`
		ValueFrom *struct {
			SecretKeyRef *struct {
				Name string `yaml:"name"`
				Key  string `yaml:"key"`
			} `yaml:"secretKeyRef"`
		} `yaml:"valueFrom"`
	} `yaml:"env"`
	StartupProbe   *probe `yaml:"startupProbe"`
	LivenessProbe  *probe `yaml:"livenessProbe"`
	ReadinessProbe *probe `yaml:"readinessProbe"`
	Resources      struct {
		Requests map[string]string `yaml:"requests"`
		Limits   map[string]string `yaml:"limits"`
	} `yaml:"resources"`
	VolumeMounts []struct {
		Name      string `yaml:"name"`
		MountPath string `yaml:"mountPath"`
		SubPath   string `yaml:"subPath"`
		ReadOnly  bool   `yaml:"readOnly"`
	} `yaml:"volumeMounts"`
}

type probe struct {
	TCPSocket *struct {
		Port string `yaml:"port"`
	} `yaml:"tcpSocket"`
	PeriodSeconds    int `yaml:"periodSeconds"`
	FailureThreshold int `yaml:"failureThreshold"`
}

// rootContainer renders the chart and returns the Deployment and its root node container.
func rootContainer(t *testing.T, args ...string) (deployment, container) {
	t.Helper()

	d := object[deployment](t, render(t, args...), "Deployment")
	for _, c := range d.Spec.Template.Spec.Containers {
		if c.Name == "krypton-root" {
			return d, c
		}
	}

	t.Fatalf("the Deployment has no container krypton-root: %+v", d.Spec.Template.Spec.Containers)

	return d, container{}
}

// env returns the environment variables of the container by name.
func env(c container) map[string]string {
	result := map[string]string{}

	for _, e := range c.Env {
		switch {
		case e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil:
			result[e.Name] = "secret " + e.ValueFrom.SecretKeyRef.Name + "/" + e.ValueFrom.SecretKeyRef.Key
		default:
			result[e.Name] = e.Value
		}
	}

	return result
}

func TestImage(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		image string
	}{
		{name: "default: the chart's appVersion", image: "ghcr.io/openkcm/krypton/images/root:" + appVersion(t)},
		{name: "tag", args: []string{"--set", "image.tag=v9.9.9"}, image: "ghcr.io/openkcm/krypton/images/root:v9.9.9"},
		{
			name:  "the digest takes precedence over the tag",
			args:  []string{"--set", "image.tag=v9.9.9", "--set", "image.digest=sha256:0123456789abcdef"},
			image: "ghcr.io/openkcm/krypton/images/root@sha256:0123456789abcdef",
		},
		{
			name:  "no registry",
			args:  []string{"--set", "image.registry=", "--set", "image.repository=krypton-root", "--set", "image.tag=dev"},
			image: "krypton-root:dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := rootContainer(t, tt.args...)
			if c.Image != tt.image {
				t.Errorf("image %q, want %q", c.Image, tt.image)
			}
		})
	}
}

func TestCommand(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		command []string
	}{
		// The release images do not start the binary with their own command.
		{name: "default: the amd64 binary of the release image", command: []string{"/root/root.linux-amd64"}},
		{name: "arm64", args: []string{"--set-json", `image.command=["/root/root.linux-arm64"]`}, command: []string{"/root/root.linux-arm64"}},
		{name: "a string", args: []string{"--set", "image.command=/bin/krypton-root"}, command: []string{"/bin/krypton-root"}},
		{name: "empty: the image's command", args: []string{"--set-json", "image.command=[]"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := rootContainer(t, tt.args...)
			if !slices.Equal(c.Command, tt.command) {
				t.Errorf("command %q, want %q", c.Command, tt.command)
			}
		})
	}
}

func TestSecurityDefaults(t *testing.T) {
	d, c := rootContainer(t)
	pod := d.Spec.Template.Spec

	if !pod.SecurityContext.RunAsNonRoot || pod.SecurityContext.RunAsUser != 65532 ||
		pod.SecurityContext.RunAsGroup != 65532 || pod.SecurityContext.FSGroup != 65532 {
		t.Errorf("pod security context: %+v", pod.SecurityContext)
	}

	if pod.SecurityContext.SeccompProfile.Type != "RuntimeDefault" {
		t.Errorf("seccomp profile %q", pod.SecurityContext.SeccompProfile.Type)
	}

	if pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		t.Error("the ServiceAccount token is mounted; the root node does not call the Kubernetes API")
	}

	if pod.EnableServiceLinks == nil || *pod.EnableServiceLinks {
		t.Error("Service environment variables are enabled")
	}

	sc := c.SecurityContext
	if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation || !sc.ReadOnlyRootFilesystem ||
		!slices.Equal(sc.Capabilities.Drop, []string{"ALL"}) {
		t.Errorf("container security context: %+v", sc)
	}

	if c.Resources.Requests["cpu"] == "" || c.Resources.Limits["memory"] == "" ||
		c.Resources.Limits["ephemeral-storage"] == "" {
		t.Errorf("resources: %+v", c.Resources)
	}

	if len(pod.ImagePullSecrets) != 0 {
		t.Errorf("image pull secrets by default: %+v", pod.ImagePullSecrets)
	}
}

func TestEnvironment(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		_, c := rootContainer(t)

		want := map[string]string{"ROOT_CONFIG_PATH": "/etc/krypton/config.yaml"}
		if got := env(c); !maps.Equal(got, want) {
			t.Errorf("environment %v, want %v", got, want)
		}
	})

	t.Run("secrets", func(t *testing.T) {
		_, c := rootContainer(t,
			"--set", "database.existingSecret=krypton-secret",
			"--set", "rootKey.existingSecret=krypton-secret",
			"--set", "extraEnvs[0].name=BAO_TOKEN", "--set", "extraEnvs[0].value=test",
		)

		want := map[string]string{
			"ROOT_CONFIG_PATH": "/etc/krypton/config.yaml",
			"DATABASE_URL":     "secret krypton-secret/database-url",
			"KRYPTON_ROOT_KEY": "secret krypton-secret/root-key",
			"BAO_TOKEN":        "test",
		}
		if got := env(c); !maps.Equal(got, want) {
			t.Errorf("environment %v, want %v", got, want)
		}
	})
}

func TestVolumes(t *testing.T) {
	d, c := rootContainer(t)

	mounts := map[string]string{}
	for _, m := range c.VolumeMounts {
		mounts[m.Name] = m.MountPath + ":" + m.SubPath
	}

	want := map[string]string{"config": "/etc/krypton/config.yaml:config.yaml", "tmp": "/tmp:"}
	if !maps.Equal(mounts, want) {
		t.Errorf("volume mounts %v, want %v", mounts, want)
	}

	for _, v := range d.Spec.Template.Spec.Volumes {
		if v.Name == "config" && (v.ConfigMap == nil || v.ConfigMap.Name != "krypton-root-config") {
			t.Errorf("config volume %+v, want ConfigMap krypton-root-config", v)
		}

		if v.Name == "tmp" && (v.EmptyDir == nil || v.EmptyDir.SizeLimit != "64Mi") {
			t.Errorf("tmp volume %+v", v)
		}
	}
}

func TestProbes(t *testing.T) {
	_, c := rootContainer(t)

	for name, p := range map[string]*probe{"startup": c.StartupProbe, "liveness": c.LivenessProbe, "readiness": c.ReadinessProbe} {
		if p == nil || p.TCPSocket == nil || p.TCPSocket.Port != "grpc" {
			t.Errorf("%s probe %+v, want a TCP check of the grpc port", name, p)
		}
	}

	// The root node migrates its database before it opens the gRPC port.
	if c.StartupProbe.PeriodSeconds*c.StartupProbe.FailureThreshold < 120 {
		t.Errorf("the startup probe allows less than 120 seconds: %+v", c.StartupProbe)
	}
}

func TestChecksumConfig(t *testing.T) {
	checksum := func(args ...string) string {
		d, _ := rootContainer(t, args...)
		return d.Spec.Template.Metadata.Annotations["checksum/config"]
	}

	defaults := checksum()
	if defaults == "" {
		t.Fatal("no checksum/config annotation")
	}

	if defaults == checksum("--set", "config.selector_labels.environment=test") {
		t.Error("the checksum does not change with the configuration")
	}

	if defaults != checksum("--set", "replicaCount=1", "--set", "pod.annotations.team=keys") {
		t.Error("the checksum changes without a configuration change")
	}
}

func TestReplicasAndStrategy(t *testing.T) {
	d, _ := rootContainer(t)
	if d.Spec.Replicas == nil || *d.Spec.Replicas != 1 || d.Spec.Strategy.Type != "Recreate" {
		t.Errorf("replicas %v, strategy %q; want 1, Recreate", d.Spec.Replicas, d.Spec.Strategy.Type)
	}

	d, _ = rootContainer(t, "--set", "hpa.enabled=true")
	if d.Spec.Replicas != nil {
		t.Errorf("replicas %d with the autoscaler", *d.Spec.Replicas)
	}
}

// TestNamesAndSelectors checks the resource names and selector labels of chart 0.0.1: a
// Deployment's selector cannot change on upgrade, and the Service name is the address of the
// root node in config.connections.
func TestNamesAndSelectors(t *testing.T) {
	output := render(t)
	want := map[string]string{
		"app.kubernetes.io/name":     "krypton-root",
		"app.kubernetes.io/instance": releaseName,
		"openkcm.io/node":            "root",
	}

	d := object[deployment](t, output, "Deployment")
	if d.Metadata.Name != "krypton-root" || !maps.Equal(d.Spec.Selector.MatchLabels, want) {
		t.Errorf("Deployment %q with selector %v, want krypton-root with %v", d.Metadata.Name,
			d.Spec.Selector.MatchLabels, want)
	}

	s := object[service](t, output, "Service")
	if s.Metadata.Name != "krypton-root" || !maps.Equal(s.Spec.Selector, want) {
		t.Errorf("Service %q with selector %v, want krypton-root with %v", s.Metadata.Name, s.Spec.Selector, want)
	}

	if cm := object[configMap](t, output, "ConfigMap"); cm.Metadata.Name != "krypton-root-config" {
		t.Errorf("ConfigMap %q, want krypton-root-config", cm.Metadata.Name)
	}

	labels := d.Spec.Template.Metadata.Labels
	if labels["app.kubernetes.io/version"] != appVersion(t) {
		t.Errorf("version label %q, want %q", labels["app.kubernetes.io/version"], appVersion(t))
	}

	d = object[deployment](t, render(t, "--set", "commonLabels.team=keys"), "Deployment")
	if d.Spec.Template.Metadata.Labels["team"] != "keys" || !maps.Equal(d.Spec.Selector.MatchLabels, want) {
		t.Errorf("commonLabels: labels %v, selector %v", d.Spec.Template.Metadata.Labels, d.Spec.Selector.MatchLabels)
	}
}
