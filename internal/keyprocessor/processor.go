package keyprocessor

import (
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault"
)

type KeyProcessor struct {
	keySpec         spec.KeySpec
	cryptor         cryptor.Cryptor
	secretGenerator cryptor.SecretGenerator // can be nil if cryptor manages its own secret, e.g. HSM cryptor
	vault           vault.Vault             // can be nil if vault is not needed
	parent          *KeyProcessor
}
