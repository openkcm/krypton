package integration

import (
	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/providertest"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
)

// Region identifiers used to name topology segments and KMIP endpoints.
const (
	region_root      = "root"
	region_ap        = "ap"
	region_eu        = "eu"
	region_germany   = "de"
	region_spain     = "es"
	region_japan     = "jp"
	region_singapore = "sg"
)

// rootLevelConfig defines a flat hierarchy where root handles all keys (K0->K1->K2).
//
//	root
//
// [k0(root) k1(tek) k2(dek)]
var rootLevelConfig = config.RootConfig{
	Name: region_root,
	Role: config.RootRole,
	Segment: spec.HierarchySegment{
		StartKind: "K0",
		EndKind:   "K2",
	},
	RootKey: &spec.RootKeySpec{
		AllowedProviders: []sealer.Type{
			providertest.TypeProviderTest,
		},
		Vault: vaultprovider.Spec{
			Name: "credentials-vault",
			Type: sqlitevault.TypeUnsafeMemory,
		},
	},
	KeyBindings: map[string]spec.KeyBinding{
		"K1": {
			CryptorSpec: &cryptorprovider.Spec{
				Name: "kek-crypto",
				Type: aes256gcm.TypeAES256GCM,
			},
			VaultSpec: &vaultprovider.Spec{
				Name: "root-vault",
				Type: sqlitevault.TypeUnsafeMemory,
			},
		},
		"K2": {
			CryptorSpec: &cryptorprovider.Spec{
				Name: "kek-crypto",
				Type: aes256gcm.TypeAES256GCM,
			},
			VaultSpec: &vaultprovider.Spec{
				Name: "root-vault",
				Type: sqlitevault.TypeUnsafeMemory,
			},
		},
	},
	Hierarchy: spec.KeyHierarchy{
		Name: "production-hierarchy",
		KeySpecs: []spec.KeySpec{
			{
				Kind:      "K0",
				Role:      spec.KeyRoleRoot,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K1",
				Role:      spec.KeyRoleTek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K2",
				Role:      spec.KeyRoleDek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
		},
	},
	Topology: spec.Topology{
		Segments: []spec.TopologySegment{},
	},
}

// regionLevelConfig defines a two-level hierarchy: root (K0-K1) delegates to
// regional agents ap and eu (K2-K3).
//
//	     root
//	[k0(root) k1(kek)]
//	  /            \
//	 /              \
//	ap              eu
//
// [k2(tek) k3(dek)]   [k2(tek) k3(dek)]
var regionLevelConfig = config.RootConfig{
	Name: region_root,
	Role: config.RootRole,
	Segment: spec.HierarchySegment{
		StartKind: "K0",
		EndKind:   "K1",
	},
	RootKey: &spec.RootKeySpec{
		AllowedProviders: []sealer.Type{
			providertest.TypeProviderTest,
		},
		Vault: vaultprovider.Spec{
			Name: "credentials-vault",
			Type: sqlitevault.TypeUnsafeMemory,
		},
	},
	KeyBindings: map[string]spec.KeyBinding{
		"K1": {
			CryptorSpec: &cryptorprovider.Spec{
				Name: "kek-crypto",
				Type: aes256gcm.TypeAES256GCM,
			},
			VaultSpec: &vaultprovider.Spec{
				Name: "root-vault",
				Type: sqlitevault.TypeUnsafeMemory,
			},
		},
	},
	Hierarchy: spec.KeyHierarchy{
		Name: "production-hierarchy",
		KeySpecs: []spec.KeySpec{
			{
				Kind:      "K0",
				Role:      spec.KeyRoleRoot,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K1",
				Role:      spec.KeyRoleKek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K2",
				Role:      spec.KeyRoleTek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K3",
				Role:      spec.KeyRoleDek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
		},
	},
	Topology: spec.Topology{
		Segments: []spec.TopologySegment{
			{
				Name: region_ap,
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: map[string]spec.KeyBinding{
					"K2": {
						SealerSpec: &sealerprovider.Spec{
							Name: "tek-sealer",
							Type: staticsecret.TypeStaticSecret,
							Config: &staticsecret.Config{
								Secret: secretprovider.Spec{
									Type:   envvar.Type,
									Config: &envvar.Config{Name: "KRYPTON_TEK_KEY"},
								},
							},
						},
						CryptorSpec: &cryptorprovider.Spec{
							Name:   "tek-crypto",
							Type:   aes256gcm.TypeAES256GCM,
							Config: &aes256gcm.Config{},
						},
						VaultSpec: &vaultprovider.Spec{
							Name:   "agent-vault",
							Type:   sqlitevault.TypeUnsafeMemory,
							Config: &sqlitevault.InMemoryConfig{},
						},
						ParentKeyProvider: &spec.ParentKeyProviderRef{
							AgentName: region_root,
						},
					},
					"K3": {
						CryptorSpec: &cryptorprovider.Spec{
							Name:   "dek-crypto",
							Type:   aes256gcm.TypeAES256GCM,
							Config: &aes256gcm.Config{},
						},
						VaultSpec: &vaultprovider.Spec{
							Name:   "agent-dek-vault",
							Type:   sqlitevault.TypeUnsafeMemory,
							Config: &sqlitevault.InMemoryConfig{},
						},
					},
				},
				SelectorLabels: spec.SelectorLabels{
					"cloud": "aws",
				},
			},
			{
				Name: region_eu,
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: map[string]spec.KeyBinding{
					"K2": {
						SealerSpec: &sealerprovider.Spec{
							Name: "tek-sealer",
							Type: staticsecret.TypeStaticSecret,
							Config: &staticsecret.Config{
								Secret: secretprovider.Spec{
									Type:   envvar.Type,
									Config: &envvar.Config{Name: "KRYPTON_TEK_KEY"},
								},
							},
						},
						CryptorSpec: &cryptorprovider.Spec{
							Name: "tek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
						ParentKeyProvider: &spec.ParentKeyProviderRef{
							AgentName: region_root,
						},
					},
					"K3": {
						CryptorSpec: &cryptorprovider.Spec{
							Name: "dek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-dek-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
					},
				},
				SelectorLabels: spec.SelectorLabels{
					"cloud": "aws",
				},
			},
		},
	},
}

// countryLevelConfig defines a three-level hierarchy: root (K0-K1) ->
// region agents eu/ap (K2-K3) -> country agents de/es/jp/sg (K4-K5).
//
//	           root
//	      [k0(root) k1(kek)]
//	        /            \
//	       /              \
//	      eu              ap
//	[k2(tek) k3(kek)]    [k2(tek) k3(kek)]
//	  /        \            /         \
//	 /          \          /           \
//	de          es        jp           sg
//
// [k4(tek) k5(dek)]    [k4(tek) k5(dek)]
var countryLevelConfig = config.RootConfig{
	Name: region_root,
	Role: config.RootRole,
	Segment: spec.HierarchySegment{
		StartKind: "K0",
		EndKind:   "K1",
	},
	RootKey: &spec.RootKeySpec{
		AllowedProviders: []sealer.Type{
			providertest.TypeProviderTest,
		},
		Vault: vaultprovider.Spec{
			Name: "credentials-vault",
			Type: sqlitevault.TypeUnsafeMemory,
		},
	},
	KeyBindings: map[string]spec.KeyBinding{
		"K1": {
			CryptorSpec: &cryptorprovider.Spec{
				Name: "kek-crypto",
				Type: aes256gcm.TypeAES256GCM,
			},
			VaultSpec: &vaultprovider.Spec{
				Name: "root-vault",
				Type: sqlitevault.TypeUnsafeMemory,
			},
		},
	},
	Hierarchy: spec.KeyHierarchy{
		Name: "production-hierarchy",
		KeySpecs: []spec.KeySpec{
			{
				Kind:      "K0",
				Role:      spec.KeyRoleRoot,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K1",
				Role:      spec.KeyRoleKek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K2",
				Role:      spec.KeyRoleTek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K3",
				Role:      spec.KeyRoleKek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K4",
				Role:      spec.KeyRoleTek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
			{
				Kind:      "K5",
				Role:      spec.KeyRoleDek,
				Algorithm: cryptor.KeyAlgorithmAES256,
				LabelsSpec: spec.LabelsSpec{
					AllowUserLabels: true,
				},
			},
		},
	},
	Topology: spec.Topology{
		Segments: []spec.TopologySegment{
			{
				Name: region_eu,
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: map[string]spec.KeyBinding{
					"K2": {
						SealerSpec: &sealerprovider.Spec{
							Name: "tek-sealer",
							Type: staticsecret.TypeStaticSecret,
							Config: &staticsecret.Config{
								Secret: secretprovider.Spec{
									Type:   envvar.Type,
									Config: &envvar.Config{Name: "KRYPTON_TEK_KEY"},
								},
							},
						},
						CryptorSpec: &cryptorprovider.Spec{
							Name: "tek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
						ParentKeyProvider: &spec.ParentKeyProviderRef{
							AgentName: region_root,
						},
					},
					"K3": {
						CryptorSpec: &cryptorprovider.Spec{
							Name: "dek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-dek-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
					},
				},
				SelectorLabels: spec.SelectorLabels{
					"cloud": "aws",
				},
			},
			{
				Name: region_ap,
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: map[string]spec.KeyBinding{
					"K2": {
						SealerSpec: &sealerprovider.Spec{
							Name: "tek-sealer",
							Type: staticsecret.TypeStaticSecret,
							Config: &staticsecret.Config{
								Secret: secretprovider.Spec{
									Type:   envvar.Type,
									Config: &envvar.Config{Name: "KRYPTON_TEK_KEY"},
								},
							},
						},
						CryptorSpec: &cryptorprovider.Spec{
							Name:   "tek-crypto",
							Type:   aes256gcm.TypeAES256GCM,
							Config: &aes256gcm.Config{},
						},
						VaultSpec: &vaultprovider.Spec{
							Name:   "agent-vault",
							Type:   sqlitevault.TypeUnsafeMemory,
							Config: &sqlitevault.InMemoryConfig{},
						},
						ParentKeyProvider: &spec.ParentKeyProviderRef{
							AgentName: region_root,
						},
					},
					"K3": {
						CryptorSpec: &cryptorprovider.Spec{
							Name:   "dek-crypto",
							Type:   aes256gcm.TypeAES256GCM,
							Config: &aes256gcm.Config{},
						},
						VaultSpec: &vaultprovider.Spec{
							Name:   "agent-dek-vault",
							Type:   sqlitevault.TypeUnsafeMemory,
							Config: &sqlitevault.InMemoryConfig{},
						},
					},
				},
				SelectorLabels: spec.SelectorLabels{
					"cloud": "aws",
				},
			},
			{
				Name: region_germany,
				Segment: spec.HierarchySegment{
					StartKind: "K4",
					EndKind:   "K5",
				},
				KeyBindings: map[string]spec.KeyBinding{
					"K4": {
						SealerSpec: &sealerprovider.Spec{
							Name: "tek-sealer",
							Type: staticsecret.TypeStaticSecret,
							Config: &staticsecret.Config{
								Secret: secretprovider.Spec{
									Type:   envvar.Type,
									Config: &envvar.Config{Name: "KRYPTON_TEK_KEY"},
								},
							},
						},
						CryptorSpec: &cryptorprovider.Spec{
							Name: "tek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
						ParentKeyProvider: &spec.ParentKeyProviderRef{
							AgentName: region_eu,
						},
					},
					"K5": {
						CryptorSpec: &cryptorprovider.Spec{
							Name: "dek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-dek-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
					},
				},
				SelectorLabels: spec.SelectorLabels{
					"cloud": "aws",
				},
			},
			{
				Name: region_spain,
				Segment: spec.HierarchySegment{
					StartKind: "K4",
					EndKind:   "K5",
				},
				KeyBindings: map[string]spec.KeyBinding{
					"K4": {
						SealerSpec: &sealerprovider.Spec{
							Name: "tek-sealer",
							Type: staticsecret.TypeStaticSecret,
							Config: &staticsecret.Config{
								Secret: secretprovider.Spec{
									Type:   envvar.Type,
									Config: &envvar.Config{Name: "KRYPTON_TEK_KEY"},
								},
							},
						},
						CryptorSpec: &cryptorprovider.Spec{
							Name: "tek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
						ParentKeyProvider: &spec.ParentKeyProviderRef{
							AgentName: region_eu,
						},
					},
					"K5": {
						CryptorSpec: &cryptorprovider.Spec{
							Name: "dek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-dek-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
					},
				},
				SelectorLabels: spec.SelectorLabels{
					"cloud": "aws",
				},
			},
			{
				Name: region_japan,
				Segment: spec.HierarchySegment{
					StartKind: "K4",
					EndKind:   "K5",
				},
				KeyBindings: map[string]spec.KeyBinding{
					"K4": {
						SealerSpec: &sealerprovider.Spec{
							Name: "tek-sealer",
							Type: staticsecret.TypeStaticSecret,
							Config: &staticsecret.Config{
								Secret: secretprovider.Spec{
									Type:   envvar.Type,
									Config: &envvar.Config{Name: "KRYPTON_TEK_KEY"},
								},
							},
						},
						CryptorSpec: &cryptorprovider.Spec{
							Name: "tek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
						ParentKeyProvider: &spec.ParentKeyProviderRef{
							AgentName: region_ap,
						},
					},
					"K5": {
						CryptorSpec: &cryptorprovider.Spec{
							Name: "dek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-dek-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
					},
				},
				SelectorLabels: spec.SelectorLabels{
					"cloud": "aws",
				},
			},
			{
				Name: region_singapore,
				Segment: spec.HierarchySegment{
					StartKind: "K4",
					EndKind:   "K5",
				},
				KeyBindings: map[string]spec.KeyBinding{
					"K4": {
						SealerSpec: &sealerprovider.Spec{
							Name: "tek-sealer",
							Type: staticsecret.TypeStaticSecret,
							Config: &staticsecret.Config{
								Secret: secretprovider.Spec{
									Type:   envvar.Type,
									Config: &envvar.Config{Name: "KRYPTON_TEK_KEY"},
								},
							},
						},
						CryptorSpec: &cryptorprovider.Spec{
							Name: "tek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
						ParentKeyProvider: &spec.ParentKeyProviderRef{
							AgentName: region_ap,
						},
					},
					"K5": {
						CryptorSpec: &cryptorprovider.Spec{
							Name: "dek-crypto",
							Type: aes256gcm.TypeAES256GCM,
						},
						VaultSpec: &vaultprovider.Spec{
							Name: "agent-dek-vault",
							Type: sqlitevault.TypeUnsafeMemory,
						},
					},
				},
				SelectorLabels: spec.SelectorLabels{
					"cloud": "aws",
				},
			},
		},
	},
}
