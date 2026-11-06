# BYOK Root Key Providers

## Context

This story adds BYOK management for Krypton root keys.

Krypton supports two custody models:

- Admin-managed key material imported into Krypton.
- Externally managed keys, initially AWS KMS.

The `--key-id` argument always identifies the Krypton root key. Provider key versions are managed internally.

The root configuration defines:

- `byok.key_material_vault` for imported key material.
- `byok.providers.allowed` for external providers.
- `byok.providers.auth_vault` for external-provider credentials.

## Valid Configuration

`Given` the root configuration contains:

```yaml
byok:
  key_material_vault:
    name: root-key-material
    type: unsafe-sqlite-memory
  providers:
    allowed:
      - aws-kms
    auth_vault:
      name: auth
      type: unsafe-sqlite-memory
```

`When` Krypton validates the configuration

`Then` validation succeeds.

## Invalid Provider Configuration

`Given` the root configuration contains:

```yaml
byok:
  key_material_vault:
    name: root-key-material
    type: unsafe-sqlite-memory
  providers:
    allowed:
      - not-supported
    auth_vault:
      name: auth
      type: unsafe-sqlite-memory
```

`When` Krypton validates the configuration

`Then` validation fails because `not-supported` is not a supported provider.

## Activation Without BYOK Material

`Given` an announced root key in the `pre-activation` state

`And` the root key has neither imported key material nor a BYOK provider binding

`When` the user activates the root key

`Then` activation fails.

## Import Key Material

`Given` an announced root key in the `pre-activation` state

`And` `root-key.raw` contains exactly 32 bytes of raw AES-256 key material

`When` the user runs:

```shell
kr byok import \
  --tenant-id <tenant-id> \
  --key-id <root-key-id> \
  --secret-file root-key.raw
```

`Then` Krypton securely imports the key material into `byok.key_material_vault`

`And` creates key version 1

`And` binds the imported material to the root key

`And` the root key can be activated.

## Duplicate Import

`Given` a root key already has imported key material or a BYOK provider binding

`When` the user attempts another initial import for the same root key

`Then` the operation fails.

## Rotate Imported Key Material

`Given` a root key uses admin-managed imported key material

`And` `root-key-v2.raw` contains exactly 32 bytes of raw AES-256 key material

`When` the user runs:

```shell
kr byok rotate \
  --tenant-id <tenant-id> \
  --key-id <root-key-id> \
  --secret-file root-key-v2.raw
```

`Then` Krypton stores the material as the next key version

`And` the new version becomes the latest key version

`And` child key material is automatically sealed with the latest key version

`And` previous key versions remain available for unsealing existing material.

> **Note:** Resealing existing child key material after imported or provider-key rotation will be added in a future iteration.

## Configure AWS KMS

`Given` `aws-kms` is listed in `byok.providers.allowed`

`And` an announced root key is in the `pre-activation` state

`When` the user runs:

```shell
kr byok aws-kms bind \
  --tenant-id <tenant-id> \
  --key-id <root-key-id> \
  --region eu-central-1 \
  --key-arn arn:aws:kms:eu-central-1:123456789012:key/example \
  ...
```

`Then` Krypton binds the AWS KMS key to the root key

`And` no AWS KMS key material enters Krypton

`And` the root key can be activated.

## Rotate AWS KMS Key

`Given` a root key is bound to AWS KMS

`When` the user runs:

```shell
kr byok aws-kms rotate-key \
  --tenant-id <tenant-id> \
  --key-id <root-key-id> \
  --key-arn arn:aws:kms:eu-central-1:123456789012:key/replacement
```

`Then` Krypton records the AWS KMS key as the next provider-key version

`And` newly created child key material is sealed with the latest provider-key version

`And` previous provider-key versions remain available for unsealing existing material.

## Rotate AWS KMS Authentication

`Given` a root key is bound to AWS KMS

`When` the user runs:

```shell
kr byok aws-kms rotate-auth \
  --tenant-id <tenant-id> \
  --key-id <root-key-id> \
  ...
```

`Then` Krypton stores the new authentication in `byok.providers.auth_vault`

`And` subsequent AWS KMS operations use the new authentication.

## Unbind AWS KMS

`Given` a root key is bound to AWS KMS

`And` the root key is not in the `active` state

`When` the user runs:

```shell
kr byok aws-kms unbind \
  --tenant-id <tenant-id> \
  --key-id <root-key-id>
```

`Then` Krypton removes the provider binding and stored authentication

`And` does not modify or schedule deletion of the AWS KMS key.

`Given` the root key is in the `active` state

`When` the user runs `kr byok aws-kms unbind`

`Then` the operation fails.

## Destroy Imported Key Material

`Given` a root key uses admin-managed imported key material

`And` the root key is in the `destroyed` state

`When` the user runs:

```shell
kr byok destroy \
  --tenant-id <tenant-id> \
  --key-id <root-key-id>
```

`Then` Krypton destroys every imported key materials.

## Reject Unsafe Destruction

`Given` a root key uses admin-managed imported key material

`And` the root key is not in the `destroyed` state

`When` the user runs `kr byok destroy`

`Then` the operation fails because the root key has not been destroyed.

## Reject Destruction For External Providers

`Given` a root key uses AWS KMS

`When` the user runs `kr byok destroy`

`Then` the operation fails because Krypton only destroys admin-managed imported key material
