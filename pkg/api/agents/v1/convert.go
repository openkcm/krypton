package v1

import (
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/agents/v1/proto"
)

// ProtoToAgentConfig converts a proto AgentConfig to a spec AgentConfig.
func ProtoToAgentConfig(pb *proto.AgentConfig) spec.AgentConfig {
	if pb == nil {
		return spec.AgentConfig{}
	}

	return spec.AgentConfig{
		Name:        pb.GetName(),
		KeyBindings: protoToKeyBindings(pb.GetKeyBindings()),
		Segment:     protoToHierarchySegment(pb.GetSegment()),
		Labels:      spec.Labels(pb.GetLabels()),
		Role:        spec.AgentRole(pb.GetRole()),
		Hierarchy:   protoToKeyHierarchy(pb.GetHierarchy()),
		KeepAlive:   spec.KeepAliveConfig(pb.GetKeepAlive()),
	}
}

// AgentConfigToProto converts a spec AgentConfig to a proto AgentConfig.
// It returns an error if VaultSpec.Params contains values not representable in protobuf Struct.
func AgentConfigToProto(cfg spec.AgentConfig) (*proto.AgentConfig, error) {
	keyBindings, err := keyBindingsToProto(cfg.KeyBindings)
	if err != nil {
		return nil, err
	}

	return &proto.AgentConfig{
		Name:        cfg.Name,
		KeyBindings: keyBindings,
		Segment:     hierarchySegmentToProto(cfg.Segment),
		Labels:      map[string]string(cfg.Labels),
		Role:        string(cfg.Role),
		Hierarchy:   keyHierarchyToProto(cfg.Hierarchy),
		KeepAlive:   int32(cfg.KeepAlive),
	}, nil
}

// --- Proto -> Spec helpers ---

func protoToKeyBindings(m map[string]*proto.KeyBinding) map[string]spec.KeyBinding {
	if m == nil {
		return nil
	}

	result := make(map[string]spec.KeyBinding, len(m))
	for k, v := range m {
		result[k] = protoToKeyBinding(v)
	}
	return result
}

func protoToKeyBinding(pb *proto.KeyBinding) spec.KeyBinding {
	if pb == nil {
		return spec.KeyBinding{}
	}

	return spec.KeyBinding{
		Vault:             protoToVaultSpec(pb.GetVault()),
		ParentKeyProvider: protoToParentKeyProviderRef(pb.GetParentKeyProvider()),
		Labels:            spec.Labels(pb.GetLabels()),
	}
}

func protoToVaultSpec(pb *proto.VaultSpec) spec.VaultSpec {
	if pb == nil {
		return spec.VaultSpec{}
	}

	var params map[string]any
	if pb.GetParams() != nil {
		params = pb.GetParams().AsMap()
	}

	return spec.VaultSpec{
		Name:   pb.GetName(),
		Type:   pb.GetType(),
		Params: params,
	}
}

func protoToParentKeyProviderRef(pb *proto.ParentKeyProviderRef) *spec.ParentKeyProviderRef {
	if pb == nil {
		return nil
	}

	return &spec.ParentKeyProviderRef{
		AgentName: pb.GetAgentName(),
	}
}

func protoToHierarchySegment(pb *proto.HierarchySegment) spec.HierarchySegment {
	if pb == nil {
		return spec.HierarchySegment{}
	}

	return spec.HierarchySegment{
		StartKind: pb.GetStartKind(),
		EndKind:   pb.GetEndKind(),
	}
}

func protoToKeyHierarchy(pb *proto.KeyHierarchy) spec.KeyHierarchy {
	if pb == nil {
		return spec.KeyHierarchy{}
	}

	return spec.KeyHierarchy{
		Name:     pb.GetName(),
		KeySpecs: protoToKeySpecs(pb.GetKeySpecs()),
	}
}

func protoToKeySpecs(pbs []*proto.KeySpec) []spec.KeySpec {
	if pbs == nil {
		return nil
	}

	result := make([]spec.KeySpec, len(pbs))
	for i, pb := range pbs {
		result[i] = protoToKeySpec(pb)
	}
	return result
}

func protoToKeySpec(pb *proto.KeySpec) spec.KeySpec {
	if pb == nil {
		return spec.KeySpec{}
	}

	return spec.KeySpec{
		Kind:      spec.KeyKind(pb.GetKind()),
		Role:      spec.KeyRole(pb.GetRole()),
		Algorithm: spec.KeyAlgorithm(pb.GetAlgorithm()),
	}
}

// --- Spec -> Proto helpers ---

func keyBindingsToProto(m map[string]spec.KeyBinding) (map[string]*proto.KeyBinding, error) {
	if m == nil {
		return nil, nil //nolint:nilnil
	}

	result := make(map[string]*proto.KeyBinding, len(m))
	for k, v := range m {
		pb, err := keyBindingToProto(v)
		if err != nil {
			return nil, err
		}
		result[k] = pb
	}
	return result, nil
}

func keyBindingToProto(kb spec.KeyBinding) (*proto.KeyBinding, error) {
	vault, err := vaultSpecToProto(kb.Vault)
	if err != nil {
		return nil, err
	}

	return &proto.KeyBinding{
		Vault:             vault,
		ParentKeyProvider: parentKeyProviderRefToProto(kb.ParentKeyProvider),
		Labels:            map[string]string(kb.Labels),
	}, nil
}

func vaultSpecToProto(vs spec.VaultSpec) (*proto.VaultSpec, error) {
	var params *structpb.Struct
	if vs.Params != nil {
		var err error
		params, err = structpb.NewStruct(vs.Params)
		if err != nil {
			return nil, err
		}
	}

	return &proto.VaultSpec{
		Name:   vs.Name,
		Type:   vs.Type,
		Params: params,
	}, nil
}

func parentKeyProviderRefToProto(ref *spec.ParentKeyProviderRef) *proto.ParentKeyProviderRef {
	if ref == nil {
		return nil
	}

	return &proto.ParentKeyProviderRef{
		AgentName: ref.AgentName,
	}
}

func hierarchySegmentToProto(hs spec.HierarchySegment) *proto.HierarchySegment {
	return &proto.HierarchySegment{
		StartKind: hs.StartKind,
		EndKind:   hs.EndKind,
	}
}

func keyHierarchyToProto(kh spec.KeyHierarchy) *proto.KeyHierarchy {
	return &proto.KeyHierarchy{
		Name:     kh.Name,
		KeySpecs: keySpecsToProto(kh.KeySpecs),
	}
}

func keySpecsToProto(specs []spec.KeySpec) []*proto.KeySpec {
	if specs == nil {
		return nil
	}

	result := make([]*proto.KeySpec, len(specs))
	for i, s := range specs {
		result[i] = keySpecToProto(s)
	}
	return result
}

func keySpecToProto(ks spec.KeySpec) *proto.KeySpec {
	return &proto.KeySpec{
		Kind:      string(ks.Kind),
		Role:      string(ks.Role),
		Algorithm: string(ks.Algorithm),
	}
}
