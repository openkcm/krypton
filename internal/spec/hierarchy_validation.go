package spec

import (
	"errors"
	"fmt"

	"github.com/openkcm/krypton/pkg/model"
)

var (
	ErrSegmentStartKindNotInHierarchy = errors.New("segment start kind not found in hierarchy")
	ErrSegmentEndKindNotInHierarchy   = errors.New("segment end kind not found in hierarchy")
	ErrSegmentStartAfterEnd           = errors.New("segment start kind must not come after end kind in hierarchy")
	ErrSegmentBindingsMissing         = errors.New("key binding missing for key kind in segment range")
	ErrSegmentBindingsExtra           = errors.New("key binding found for key kind outside segment range")

	ErrRootSegmentStartNotFirst        = errors.New("root segment must start at hierarchy's first key")
	ErrRootSegmentEndIsTek             = errors.New("root segment end kind must not have role tek")
	ErrRootBindingHasParentKeyProvider = errors.New("root key binding must not have a parent key provider")
	ErrRootBindingMissingSealer        = errors.New("root key binding must have a sealer")
	ErrRootBindingHasCryptor           = errors.New("root key binding must not have a cryptor")

	ErrAgentSegmentStartNotTek                   = errors.New("agent segment must start with a tek role key")
	ErrAgentSegmentEndIsTek                      = errors.New("agent segment end kind must not have role tek unless single-key segment")
	ErrAgentSegmentEndIsRoot                     = errors.New("agent segment end kind must not have role root")
	ErrAgentSegmentContainsRoot                  = errors.New("agent segment must not contain the root role key")
	ErrAgentSegmentStartMissingParentKeyProvider = errors.New("agent segment tek start key must have a parent key provider")

	ErrTekBindingMissingSealer = errors.New("tek key binding must have a sealer")
	ErrBindingMissingCryptor   = errors.New("key binding must have a cryptor")

	ErrTopologyDuplicateSegmentName           = errors.New("duplicate topology segment name")
	ErrParentKeyProviderNotResolvable         = errors.New("parent key provider agent name does not resolve to root or any topology segment")
	ErrParentKeyProviderKeyNotInParentSegment = errors.New("parent key provider's segment does not contain the parent key kind")
)

// ValidateSegmentAgainstHierarchy checks that a segment's endpoints exist in the hierarchy are in the correct order, and that bindings cover exactly the segment range.
func ValidateSegmentAgainstHierarchy(h KeyHierarchy, seg HierarchySegment, bindings map[string]KeyBinding) error {
	startIdx := h.IndexOf(model.KeyKind(seg.StartKind))
	if startIdx < 0 {
		return fmt.Errorf("%w: %q", ErrSegmentStartKindNotInHierarchy, seg.StartKind)
	}
	endIdx := h.IndexOf(model.KeyKind(seg.EndKind))
	if endIdx < 0 {
		return fmt.Errorf("%w: %q", ErrSegmentEndKindNotInHierarchy, seg.EndKind)
	}
	if startIdx > endIdx {
		return ErrSegmentStartAfterEnd
	}

	kindsInRange := h.KeySpecs[startIdx : endIdx+1]

	rangeSet := make(map[string]struct{}, len(kindsInRange))
	for _, ks := range kindsInRange {
		kind := string(ks.Kind)
		rangeSet[kind] = struct{}{}
		if _, exists := bindings[kind]; !exists {
			return fmt.Errorf("%w: %q", ErrSegmentBindingsMissing, kind)
		}
	}

	for kind := range bindings {
		if _, inRange := rangeSet[kind]; !inRange {
			return fmt.Errorf("%w: %q", ErrSegmentBindingsExtra, kind)
		}
	}

	return nil
}

// ValidateRootSegment validates the root's segment against the hierarchy, enforcing root-specific constraints.
func ValidateRootSegment(h KeyHierarchy, seg HierarchySegment, bindings map[string]KeyBinding) error {
	if err := ValidateSegmentAgainstHierarchy(h, seg, bindings); err != nil {
		return err
	}

	startIdx := h.IndexOf(model.KeyKind(seg.StartKind))
	if startIdx != 0 {
		return ErrRootSegmentStartNotFirst
	}

	endSpec, _ := h.FindKeySpec(model.KeyKind(seg.EndKind))
	if endSpec.Role == KeyRoleTek {
		return ErrRootSegmentEndIsTek
	}

	rootBinding, exists := bindings[seg.StartKind]
	if !exists {
		return fmt.Errorf("%w: %q", ErrSegmentBindingsMissing, seg.StartKind)
	}
	if rootBinding.ParentKeyProvider != nil {
		return ErrRootBindingHasParentKeyProvider
	}
	if rootBinding.SealerSpec == nil {
		return ErrRootBindingMissingSealer
	}
	if rootBinding.CryptorSpec != nil {
		return ErrRootBindingHasCryptor
	}

	// Non-root keys in root segment must have a cryptor
	kindsInRange, err := h.KindsBetween(model.KeyKind(seg.StartKind), model.KeyKind(seg.EndKind))
	if err != nil {
		return err
	}
	for _, ks := range kindsInRange {
		if ks.Role == KeyRoleRoot {
			continue
		}
		binding := bindings[string(ks.Kind)]
		if binding.CryptorSpec == nil {
			return fmt.Errorf("%w: %q", ErrBindingMissingCryptor, ks.Kind)
		}
	}

	return nil
}

// ValidateAgentSegment validates an agent's topology segment against the hierarchy enforcing agent-specific constraints.
func ValidateAgentSegment(h KeyHierarchy, seg HierarchySegment, bindings map[string]KeyBinding) error {
	if err := ValidateSegmentAgainstHierarchy(h, seg, bindings); err != nil {
		return err
	}

	startSpec, _ := h.FindKeySpec(model.KeyKind(seg.StartKind))
	if startSpec.Role != KeyRoleTek {
		return ErrAgentSegmentStartNotTek
	}

	isSingleKey := seg.StartKind == seg.EndKind
	if !isSingleKey {
		endSpec, _ := h.FindKeySpec(model.KeyKind(seg.EndKind))
		if endSpec.Role == KeyRoleRoot {
			return ErrAgentSegmentEndIsRoot
		}
		if endSpec.Role == KeyRoleTek {
			return ErrAgentSegmentEndIsTek
		}
	}

	kindsInRange, _ := h.KindsBetween(model.KeyKind(seg.StartKind), model.KeyKind(seg.EndKind))
	for _, ks := range kindsInRange {
		if ks.Role == KeyRoleRoot {
			return ErrAgentSegmentContainsRoot
		}
	}

	startBinding, exists := bindings[seg.StartKind]
	if !exists {
		return fmt.Errorf("%w: %q", ErrSegmentBindingsMissing, seg.StartKind)
	}
	if startBinding.ParentKeyProvider == nil {
		return ErrAgentSegmentStartMissingParentKeyProvider
	}
	if startBinding.SealerSpec == nil {
		return ErrTekBindingMissingSealer
	}

	// All keys in agent segment must have a cryptor
	for _, ks := range kindsInRange {
		binding := bindings[string(ks.Kind)]
		if binding.CryptorSpec == nil {
			return fmt.Errorf("%w: %q", ErrBindingMissingCryptor, ks.Kind)
		}
	}

	return nil
}

// ValidateTopologyAgainstHierarchy validates the entire topology against the hierarchy checking agent segment rules,
// name uniqueness, and parent key provider resolution.
func ValidateTopologyAgainstHierarchy(h KeyHierarchy, t Topology, rootSeg HierarchySegment, rootBindings map[string]KeyBinding) error {
	uniqSegs := make(map[string]struct{}, len(t.Segments))
	for _, seg := range t.Segments {
		if _, exists := uniqSegs[seg.Name]; exists {
			return fmt.Errorf("%w: %q", ErrTopologyDuplicateSegmentName, seg.Name)
		}
		uniqSegs[seg.Name] = struct{}{}
	}

	for i, seg := range t.Segments {
		if err := ValidateAgentSegment(h, seg.Segment, seg.KeyBindings); err != nil {
			return fmt.Errorf("segment %q (index %d): %w", seg.Name, i, err)
		}
	}

	providers := make(map[string]HierarchySegment, len(t.Segments)+1)
	providers["root"] = rootSeg
	for _, seg := range t.Segments {
		providers[seg.Name] = seg.Segment
	}

	if err := validateBindingsParentProviders(h, rootBindings, rootSeg, providers); err != nil {
		return fmt.Errorf("root bindings: %w", err)
	}

	for _, seg := range t.Segments {
		if err := validateBindingsParentProviders(h, seg.KeyBindings, seg.Segment, providers); err != nil {
			return fmt.Errorf("segment %q: %w", seg.Name, err)
		}
	}

	return nil
}

// validateBindingsParentProviders checks that all ParentKeyProvider references in a set of bindings resolve to known providers and that the parent key falls within the provider's segment.
func validateBindingsParentProviders(h KeyHierarchy, bindings map[string]KeyBinding, ownerSeg HierarchySegment, providers map[string]HierarchySegment) error {
	for kind, binding := range bindings {
		if binding.ParentKeyProvider == nil {
			continue
		}
		providerName := binding.ParentKeyProvider.AgentName
		providerSeg, exists := providers[providerName]
		if !exists {
			return fmt.Errorf("%w: %q (referenced by key kind %q)", ErrParentKeyProviderNotResolvable, providerName, kind)
		}

		kindIdx := h.IndexOf(model.KeyKind(kind))
		if kindIdx <= 0 {
			continue
		}

		parentKind := h.KeySpecs[kindIdx-1].Kind
		parentIdx := h.IndexOf(parentKind)
		providerStartIdx := h.IndexOf(model.KeyKind(providerSeg.StartKind))
		providerEndIdx := h.IndexOf(model.KeyKind(providerSeg.EndKind))
		if providerStartIdx >= 0 && providerEndIdx >= 0 {
			if parentIdx < providerStartIdx || parentIdx > providerEndIdx {
				return fmt.Errorf("%w: parent key kind %q not in segment %q (%s→%s)",
					ErrParentKeyProviderKeyNotInParentSegment, parentKind, providerName, providerSeg.StartKind, providerSeg.EndKind)
			}
		}
	}
	return nil
}
