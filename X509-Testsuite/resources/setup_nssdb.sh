#!/usr/bin/env bash
set -euo pipefail

# Define paths
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NSS_DB="$BASE_DIR/nss_db"
ROOT_DIR="$BASE_DIR/static-root"
OUT_DIR="$BASE_DIR/out"

# Ensure required tools are installed
for cmd in certutil pk12util openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: Required command '$cmd' not found. Please install libnss3-tools and openssl." >&2
        exit 11
    fi
done

echo "Creating NSS DB at: $NSS_DB"
mkdir -p "$NSS_DB"

rm -f "$NSS_DB/cert9.db"
rm -f "$NSS_DB/key4.db"
rm -f "$NSS_DB/pkcs11.txt"

echo "Initializing NSS DB..."
certutil -N -d "sql:$NSS_DB" --empty-password

echo "Creating PKCS#12 container..."
openssl pkcs12 -export \
  -inkey "$ROOT_DIR/private-key.pem" \
  -in "$ROOT_DIR/root-cert.pem" \
  -out "$ROOT_DIR/x509_anvil_nss_server.p12" \
  -name "nss-server-cert" \
  -passout pass:password

echo "Importing PKCS#12 container into NSS DB..."
pk12util -i "$ROOT_DIR/x509_anvil_nss_server.p12" -d "sql:$NSS_DB" -W "password"

echo "Adding CA certificate..."
certutil -A -n "X509-Anvil-CA" -t "CT,," -i "$OUT_DIR/root_cert.pem" -d "sql:$NSS_DB"

echo "✅ NSS DB setup complete!"