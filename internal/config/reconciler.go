package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

var (
	ErrReconcilerConfigNil          = errors.New("reconciler config cannot be nil")
	ErrReconcilerTargetNameEmpty    = errors.New("target name cannot be empty")
	ErrReconcilerTargetAddressEmpty = errors.New("target address cannot be empty")
	ErrReconcilerTargetDuplicate    = errors.New("duplicate target name")
)

// ReconcilerConfig describes the process-level Orbital reconciler service.
type ReconcilerConfig struct {
	Targets           []ReconcilerTarget `yaml:"targets"`
	MaxReconcileCount uint64             `yaml:"maxReconcileCount"`
}

// ReconcilerTarget describes one gRPC target that can receive Orbital task requests.
type ReconcilerTarget struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
}

// LoadReconcilerConfig reads either a direct reconciler config document or a
// document with a top-level "reconciler" section.
func LoadReconcilerConfig(path string) (*ReconcilerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read reconciler config: %w", err)
	}

	var wrapped struct {
		Reconciler *ReconcilerConfig `yaml:"reconciler"`
	}
	if err := yaml.Unmarshal(data, &wrapped); err != nil {
		return nil, fmt.Errorf("parse reconciler config: %w", err)
	}

	var cfg ReconcilerConfig
	if wrapped.Reconciler != nil {
		cfg = *wrapped.Reconciler
	} else if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse reconciler config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *ReconcilerConfig) Validate() error {
	seen := make(map[string]struct{}, len(c.Targets))
	for _, target := range c.Targets {
		if target.Name == "" {
			return ErrReconcilerTargetNameEmpty
		}
		if target.Address == "" {
			return fmt.Errorf("%w: %s", ErrReconcilerTargetAddressEmpty, target.Name)
		}
		if _, ok := seen[target.Name]; ok {
			return fmt.Errorf("%w: %s", ErrReconcilerTargetDuplicate, target.Name)
		}
		seen[target.Name] = struct{}{}
	}

	return nil
}
