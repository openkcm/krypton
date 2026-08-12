#!/bin/bash
set -euo pipefail

# Usage: ./generate-server-certs.sh [output_dir]
# Example: ./generate-server-certs.sh ./certs
#
# Generates:
#   - CA certificate and key
#   - Server certificate and key (signed by CA)

OUTPUT_DIR="${1:-./certs}"
DAYS_VALID=365

mkdir -p "$OUTPUT_DIR"

echo "Output directory: $OUTPUT_DIR"

# --- CA Certificate ---
echo "[1/2] Generating CA certificate..."
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout "$OUTPUT_DIR/ca-key.pem" \
  -out "$OUTPUT_DIR/ca.pem" \
  -days "$DAYS_VALID" \
  -subj "/CN=test-ca" \
  2>/dev/null

# --- Server Certificate (for KMIP server) ---
echo "[2/2] Generating server certificate..."
cat > "$OUTPUT_DIR/server-ext.cnf" <<EOF
[req]
distinguished_name = req_dn
req_extensions = v3_req
prompt = no

[req_dn]
CN = kmip-server

[v3_req]
subjectAltName = DNS:host.docker.internal,DNS:localhost,DNS:krypton,IP:127.0.0.1
EOF

openssl req -newkey rsa:4096 -nodes \
  -keyout "$OUTPUT_DIR/server-key.pem" \
  -out "$OUTPUT_DIR/server.csr" \
  -subj "/CN=kmip-server" \
  2>/dev/null

openssl x509 -req \
  -in "$OUTPUT_DIR/server.csr" \
  -CA "$OUTPUT_DIR/ca.pem" \
  -CAkey "$OUTPUT_DIR/ca-key.pem" \
  -CAcreateserial \
  -out "$OUTPUT_DIR/server.pem" \
  -days "$DAYS_VALID" \
  -extfile "$OUTPUT_DIR/server-ext.cnf" \
  -extensions v3_req \
  2>/dev/null

# --- Cleanup temp files ---
rm -f "$OUTPUT_DIR"/*.csr "$OUTPUT_DIR"/*.srl "$OUTPUT_DIR"/server-ext.cnf

echo ""
echo "Done! Generated certificates:"
echo "  CA cert: $OUTPUT_DIR/ca.pem"
echo "  CA key:  $OUTPUT_DIR/ca-key.pem"
echo "  Server cert: $OUTPUT_DIR/server.pem"
echo "  Server key:  $OUTPUT_DIR/server-key.pem"
