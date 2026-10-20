# Krypton root node Helm chart

The chart `krypton-root` deploys the root node of [Krypton](https://github.com/openkcm/krypton),
the OpenKCM component that creates and operates cryptographic keys. The root node is the top of
a Krypton key hierarchy: it creates and holds the keys of the first key kinds (for example the
tenant root keys and the key encryption keys), stores key metadata in PostgreSQL, and serves the
gRPC APIs for tenants, keys, actions and agents on one port. Krypton agents hold the lower key
kinds and get their parent keys from the root node. An optional KMIP server serves keys to KMIP
clients.

> [!WARNING]
> Krypton is in development and not intended for production use yet. The default
> configuration keeps all keys in the pod's memory: they are lost when the pod stops.

[values.yaml](values.yaml) documents every value and the whole root node configuration.

## What the chart creates

| Resource | Purpose |
| --- | --- |
| Deployment | The root node pod |
| ConfigMap | The root node configuration, rendered from `config` and mounted as `/etc/krypton/config.yaml` |
| Service | The gRPC APIs (8080), and the KMIP server if you add its port |
| ServiceAccount | Identity of the pod. Its token is not mounted: the root node does not call the Kubernetes API |
| NetworkPolicy | Optional (`networkPolicy.enabled`): who may reach the pod |
| PodDisruptionBudget | Optional (`pod.disruptionBudget.enabled`) |
| HorizontalPodAutoscaler | Optional (`hpa.enabled`), only with a shared vault |

The resources are named `krypton-root` (or the release name, if it contains `krypton-root`).
The Service name is part of the root node's address, which the agents use.

## Prerequisites

- Kubernetes 1.23 or later, Helm 3.
- PostgreSQL. The root node creates its tables at startup, so its database user needs to own
  the database or have `CREATE` on its schema.
- A Secret with the PostgreSQL URL and the root key. The root key seals the tenant root keys:
  32 random bytes, base64-encoded. Keep a backup of it; without it the root keys cannot be
  unsealed.
- amd64 nodes, or set `image.command` for arm64 nodes (see [Image](#image)).

## Install

Create the Secret:

```sh
kubectl -n services create secret generic krypton-secret \
  --from-literal=database-url='postgres://krypton:<password>@postgresql.services:5432/krypton?sslmode=verify-full' \
  --from-literal=root-key="$(openssl rand -base64 32)"
```

To keep the keys across restarts in development, give the root node a volume for SQLite vault
files:

```sh
kubectl -n services apply -f - <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: krypton-root-vault-data
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
EOF
```

Create a values file, for example `krypton-root.yaml`:

```yaml
database:
  existingSecret: krypton-secret
rootKey:
  existingSecret: krypton-secret

networkPolicy:
  enabled: true
  grpc:
    from:
      - namespaceSelector:
          matchLabels: { kubernetes.io/metadata.name: services }

extraVolumes:
  - name: vault-data
    persistentVolumeClaim: { claimName: krypton-root-vault-data }
extraVolumeMounts:
  - name: vault-data
    mountPath: /var/lib/krypton

config:
  key_bindings:
    K1:
      vault: { name: kek-vault, type: unsafe-sqlite, config: { path: /var/lib/krypton/kek.db } }
    K2:
      vault: { name: dek-vault, type: unsafe-sqlite, config: { path: /var/lib/krypton/dek.db } }
```

Install the chart:

```sh
helm install krypton-root oci://ghcr.io/openkcm/charts/krypton-root \
  --version 0.1.0 -n services -f krypton-root.yaml
```

The release notes show the address of the gRPC APIs and warn about values with which the root
node would not start or would be exposed. Call the APIs with the `kr` CLI (`make cli` in the
Krypton repository):

```sh
kubectl -n services port-forward service/krypton-root 8080:grpc
kr login no-auth
kr --server localhost:8080 get tenants
```

## Ports

| Port | Serves |
| --- | --- |
| `grpc` (8080) | The gRPC APIs: `TenantService`, `KeyService`, `ActionService` and the agent `Service` |
| `kmip` (`config.kmip.port`, if configured) | KMIP `Get` and `GetAttributes` |

The root node has no HTTP health endpoint; the probes check that the gRPC port accepts
connections. The startup probe allows 120 seconds, because the root node migrates its database
before it opens the port.

## Important values

| Value | Default | Description |
| --- | --- | --- |
| `image.tag` / `image.digest` | chart's `appVersion` | The Krypton version to deploy |
| `image.command` | `[/root/root.linux-amd64]` | The binary in the release image (see [Image](#image)) |
| `database.existingSecret` | `""` | Secret with the PostgreSQL URL (`DATABASE_URL`). Required |
| `rootKey.existingSecret` | `""` | Secret with the root key (`KRYPTON_ROOT_KEY`). Required with the default configuration |
| `config.key_bindings` | K0 sealed with the root key, K1 and K2 in memory | How the keys of each kind are protected and stored |
| `config.hierarchy` | K0 `root`, K1 `kek`, K2 `dek` | The key kinds |
| `config.topology` | no agents | The agents and the key kinds they manage |
| `config.connections` | `root` at `krypton-root:8080` | The gRPC addresses of the root node and the agents |
| `config.auth` | not set | Mutual TLS on the gRPC port |
| `config.kmip` | not set | KMIP server |
| `replicaCount` / `strategy` | `1` / `Recreate` | Keep them with the development vaults |
| `networkPolicy.enabled` | `false` | Restrict who may reach the gRPC APIs and the KMIP server |
| `resources` | 100m CPU, 128Mi memory and 64Mi ephemeral storage requested; 512Mi memory and 256Mi ephemeral storage limits | |

## Image

Release images are published as `ghcr.io/openkcm/krypton/images/root`, for amd64 and arm64.
They contain the binary at `/root/root.linux-<architecture>`, and their own command does not
start it. The chart therefore sets `image.command` to the amd64 binary. On arm64 nodes set:

```yaml
image:
  command: [/root/root.linux-arm64]
```

or pin the pod to amd64 nodes with `pod.nodeSelector: { kubernetes.io/arch: amd64 }`. For an
image built from `cmd/root/Dockerfile`, set `image.command: [/bin/krypton-root]`.

## Key storage

Each key kind of the root node's segment has a key binding (`config.key_bindings`): the root
kind is sealed with a secret from outside Krypton (the root key), and every other kind is
encrypted with key material that Krypton generates and stores, sealed by its parent key, in a
vault:

| Vault type | Stores in | Use |
| --- | --- | --- |
| `unsafe-sqlite-memory` | The pod's memory; lost when the pod stops | Development (default) |
| `unsafe-sqlite` | A SQLite file on a volume (`config.path`) | Development |
| `openbao` | OpenBao (`config.address`), one namespace per tenant; token and CA from `BAO_TOKEN` and `BAO_CACERT` in `extraEnvs` | Shared vault |

With the SQLite vaults, each pod has its own vault: run one replica and keep the `Recreate`
strategy, so that the old pod stops before the new one starts. A ReadWriteOnce volume cannot be
mounted by two pods on different nodes.

## Agents

To let Krypton agents manage the lower key kinds, end the root node's `config.segment` before
them, describe each agent in `config.topology.segments`, and list the address of every agent and
of the root node in `config.connections`. The root node's own entry is the address at which the
agents reach this chart's Service, for example `krypton-root.services.svc:8080`. values.yaml
has an example of each.

## Mutual TLS

Without `config.auth`, the gRPC port accepts plaintext connections from every client that can
reach it, including calls to the admin APIs. Restrict the callers with `networkPolicy` or a
service mesh, or configure `config.auth`: the gRPC port then requires TLS 1.3, and every client
must present a certificate issued by the configured CA with exactly one URI SAN, one of the
`config.auth.identity` URIs. Mount the certificates and keys from a Secret with `extraVolumes`
and `extraVolumeMounts`; values.yaml describes the PEM formats at `extraVolumes` and has an
example at `config.auth`.

## KMIP server

With `config.kmip`, the root node runs a KMIP server for keys of its segment. It requires TLS
1.3 and a client certificate issued by `config.kmip.tls.ca_path`; the common name of the client
certificate must equal the tenant ID of the keys it requests. Add the port to `ports` and
`service.ports` (examples in values.yaml) and restrict its clients with `networkPolicy.kmip.from`.

## Security defaults

| Setting | Default |
| --- | --- |
| Pod | User and group 65532 (non-root), `RuntimeDefault` seccomp profile, no Service environment variables, no ServiceAccount token |
| Container | No privilege escalation, all capabilities dropped, read-only root filesystem, writable `/tmp` |
| Memory | Key material in locked memory; the process is not dumpable and writes no core files |
| Service | `ClusterIP` |
| Secrets | From Kubernetes Secrets, as environment variables; nothing secret in the ConfigMap |

## Network policy

With `networkPolicy.enabled: true`, the chart allows ingress only from the peers in
`networkPolicy.grpc.from` (gRPC APIs) and `networkPolicy.kmip.from` (KMIP server). An empty list
denies all callers of that port. Outgoing traffic (PostgreSQL, the agents, OpenBao) is not
restricted. Probes from the kubelet are not affected on most network plugins.

## Configuration changes

The root node reads its configuration at startup. The chart adds a `checksum/config` annotation
to the pod, so a configuration change restarts it during `helm upgrade`.

Everything under `config` except `isImmutable` is written to `config.yaml`. The root node checks
the configuration at startup and exits if it is not consistent, but it ignores keys it does not
know: check the spelling of the keys against values.yaml.

## Upgrading from 0.0.1

| Change | Action |
| --- | --- |
| The default image is `ghcr.io/openkcm/krypton/images/root` with the tag from the chart's `appVersion`, started with `/root/root.linux-amd64` (was `images/krypton-root:latest` with `/bin/krypton-root`) | If you set `image.*` yourself, check them; on arm64 nodes set `image.command` |
| `extraPorts` is now `ports`, and `image.pullSecrets` is now `imagePullSecrets` (default empty, was `registry-access`) | Move your values; the chart stops with an error while the old keys are set |
| The PostgreSQL URL and the root key can come from `database.existingSecret` and `rootKey.existingSecret` | Optional: `DATABASE_URL` and `KRYPTON_ROOT_KEY` in `extraEnvs` still work |
| `config.connections` has an entry for the root node (`krypton-root:8080`). Krypton releases after v0.1.0 require it | If you replace `config.connections`, keep an entry named like `config.name` |
| New security defaults (user and group 65532, read-only root filesystem, dropped capabilities, `RuntimeDefault` seccomp profile, no ServiceAccount token, no Service environment variables) | The release image runs as this user. A volume for an `unsafe-sqlite` vault must be writable for group 65532, or set `pod.securityContext.fsGroup` |
| One replica with the `Recreate` strategy; startup, liveness and readiness probes on the gRPC port; resource requests and limits | Override `strategy`, the probes and `resources` if needed |
| The configuration is mounted as the file `/etc/krypton/config.yaml` | Do not mount other files over `/etc/krypton` |
| The environment variables `MY_POD_IP`, `K8S_NODE_NAME` and `K8S_NODE_IP`, which the root node does not read, are no longer set | None |
| A PodDisruptionBudget without `minAvailable` or `maxUnavailable` uses `maxUnavailable: 1` (was `minAvailable: 1`) | Set `pod.disruptionBudget.minAvailable` if you need the old behavior |

Resource names and selector labels are unchanged.

## Upgrading Krypton beyond v0.1.0

This chart documents the configuration of the Krypton releases after v0.1.0, and its default
configuration works with v0.1.0 as well. When you move from v0.1.0 to a later release:

| v0.1.0 | Later releases |
| --- | --- |
| `server.tls` and `authentication.allowed_cns` | `auth` with `type: mtls`, `identity` URIs and `config.server` and `config.client` |
| TLS file keys `server_cert`, `server_key`, `client_ca` (for example in `kmip.tls`) | `cert_path`, `key_path`, `ca_path` |
| No `connections` | `connections` with an entry for the root node and each agent |

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| The container does not start and the error names `/root` | `image.command` is empty: the release image's own command does not start the binary |
| `exec format error` | The binary of `image.command` does not match the node's architecture |
| Pod exits with `DATABASE_URL environment variable is required` | `database.existingSecret` is not set |
| Pod exits with `failed to run migrations` | PostgreSQL is not reachable with the URL, or the user may not create tables |
| Pod exits with `no connection config for root "root"` | `config.connections` has no entry for the root node |
| Pod exits with `environment variable is empty or not set: KRYPTON_ROOT_KEY` | `rootKey.existingSecret` is not set, or the Secret has no key `rootKey.key` |
| Pod exits with `kmip: invalid TLS configuration` | `config.kmip.tls` misses a file, for example because it uses the v0.1.0 key names |
| New pod stays `Pending` with `Multi-Attach error` | Rolling update with a ReadWriteOnce vault volume: use `strategy: { type: Recreate }` |
| Keys are gone after a restart | `unsafe-sqlite-memory` vaults keep keys only in memory |
| Upgrade fails with `field is immutable` on the ConfigMap | `config.isImmutable` is true: delete the ConfigMap `krypton-root-config` before the upgrade |
| `helm` stops with `extraPorts was renamed to ports` | Values of chart 0.0.1; see [Upgrading from 0.0.1](#upgrading-from-001) |

## Uninstall

```sh
helm uninstall krypton-root -n services
```

The Secret, the PersistentVolumeClaim and the database are not deleted.
