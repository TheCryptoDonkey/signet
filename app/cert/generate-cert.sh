#!/bin/bash
CERT_DIR="$(cd "$(dirname "$0")" && pwd)"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -days 365 -nodes \
  -keyout "$CERT_DIR/signet-key.pem" \
  -out "$CERT_DIR/signet.pem" \
  -subj "/CN=Signet Local Dev" \
  -addext "subjectAltName=DNS:localhost,DNS:*.local,IP:127.0.0.1,IP:10.10.10.60,IP:172.17.0.1,IP:192.168.1.1,IP:10.0.2.15"

# Copy to public dirs for download from both apps
cp "$CERT_DIR/signet.pem" "$CERT_DIR/../public/signet.pem"
mkdir -p "$CERT_DIR/../../family-app/public"
cp "$CERT_DIR/signet.pem" "$CERT_DIR/../../family-app/public/signet.pem"

echo "Certificate generated and copied to both app public directories."
