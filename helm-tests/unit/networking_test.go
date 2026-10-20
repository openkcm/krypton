//go:build helmtests

package unit_test

import (
	"slices"
	"strings"
	"testing"
)

// service is the part of the Service that the tests check.
type service struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Type     string            `yaml:"type"`
		Selector map[string]string `yaml:"selector"`
		Ports    []struct {
			Name       string `yaml:"name"`
			Port       int    `yaml:"port"`
			TargetPort string `yaml:"targetPort"`
		} `yaml:"ports"`
	} `yaml:"spec"`
}

// networkPolicy is the part of the NetworkPolicy that the tests check.
type networkPolicy struct {
	Spec struct {
		PolicyTypes []string `yaml:"policyTypes"`
		Ingress     []struct {
			Ports []struct {
				Port string `yaml:"port"`
			} `yaml:"ports"`
			From []map[string]any `yaml:"from"`
		} `yaml:"ingress"`
	} `yaml:"spec"`
}

func TestService(t *testing.T) {
	s := object[service](t, render(t), "Service")

	if s.Spec.Type != "ClusterIP" || len(s.Spec.Ports) != 1 || s.Spec.Ports[0].Name != "grpc" ||
		s.Spec.Ports[0].Port != 8080 || s.Spec.Ports[0].TargetPort != "grpc" {
		t.Errorf("Service %+v, want ClusterIP with port grpc 8080", s.Spec)
	}
}

// TestKMIPPortExamples renders the port examples of values.yaml for the KMIP server and checks
// that the Service port targets the container port.
func TestKMIPPortExamples(t *testing.T) {
	values := "service:\n  ports:\n" + indent(valuesComment(t, "server (`config.kmip`), add its port:"), "    ") +
		"ports:\n" + indent(valuesComment(t, "With the KMIP server, add its port (`config.kmip.port`):"), "  ")
	output := render(t, "-f", writeValues(t, values))

	s := object[service](t, output, "Service")
	_, c := rootContainer(t, "-f", writeValues(t, values))

	var containerPorts []string
	for _, p := range c.Ports {
		containerPorts = append(containerPorts, p.Name)
	}

	for _, p := range s.Spec.Ports {
		if !slices.Contains(containerPorts, p.TargetPort) {
			t.Errorf("Service port %s targets %q, which is not a container port %v", p.Name, p.TargetPort, containerPorts)
		}
	}

	if !slices.Contains(containerPorts, "kmip") {
		t.Errorf("the example has no container port kmip: %v", containerPorts)
	}
}

func TestNetworkPolicy(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		if policies := objects[networkPolicy](t, render(t), "NetworkPolicy"); len(policies) != 0 {
			t.Errorf("%d NetworkPolicies by default", len(policies))
		}
	})

	t.Run("enabled without peers denies all ingress", func(t *testing.T) {
		np := object[networkPolicy](t, render(t, "--set", "networkPolicy.enabled=true"), "NetworkPolicy")
		if !slices.Equal(np.Spec.PolicyTypes, []string{"Ingress"}) || len(np.Spec.Ingress) != 0 {
			t.Errorf("NetworkPolicy %+v, want Ingress without rules", np.Spec)
		}
	})

	t.Run("peers per port", func(t *testing.T) {
		values := "networkPolicy:\n  enabled: true\n  grpc:\n    from:\n" +
			indent(valuesComment(t, "NetworkPolicy peer syntax, for example:"), "      ") +
			"  kmip:\n    from:\n      - ipBlock: { cidr: 10.0.0.0/8 }\n"
		np := object[networkPolicy](t, render(t, "-f", writeValues(t, values)), "NetworkPolicy")

		var rules []string
		for _, rule := range np.Spec.Ingress {
			rules = append(rules, rule.Ports[0].Port+":"+strings.Repeat("peer,", len(rule.From)))
		}

		if !slices.Equal(rules, []string{"grpc:peer,peer,", "kmip:peer,"}) {
			t.Errorf("ingress rules %v", rules)
		}
	})
}
