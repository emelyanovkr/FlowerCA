#!/usr/bin/env sh

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUTPUT_DIR="$SCRIPT_DIR/generated"
PASSWORD="${FLOWERCA_TEST_CA_PASSWORD:-changeit}"

if [ -e "$OUTPUT_DIR" ]; then
    echo "Refusing to overwrite existing CA material: $OUTPUT_DIR" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
umask 077

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:4096 \
    -aes-256-cbc \
    -pass pass:"$PASSWORD" \
    -out "$OUTPUT_DIR/root-ca.key.pem"

openssl req \
    -x509 \
    -new \
    -sha256 \
    -days 3650 \
    -key "$OUTPUT_DIR/root-ca.key.pem" \
    -passin pass:"$PASSWORD" \
    -subj "/C=RU/O=FlowerCA Development/CN=FlowerCA Test Root CA" \
    -addext "basicConstraints=critical,CA:true,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -out "$OUTPUT_DIR/root-ca.cert.pem"

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:3072 \
    -aes-256-cbc \
    -pass pass:"$PASSWORD" \
    -out "$OUTPUT_DIR/intermediate-ca.key.pem"

openssl req \
    -new \
    -sha256 \
    -key "$OUTPUT_DIR/intermediate-ca.key.pem" \
    -passin pass:"$PASSWORD" \
    -subj "/C=RU/O=FlowerCA Development/CN=FlowerCA Test Intermediate CA" \
    -out "$OUTPUT_DIR/intermediate-ca.csr.pem"

openssl x509 \
    -req \
    -sha256 \
    -days 1825 \
    -in "$OUTPUT_DIR/intermediate-ca.csr.pem" \
    -CA "$OUTPUT_DIR/root-ca.cert.pem" \
    -CAkey "$OUTPUT_DIR/root-ca.key.pem" \
    -passin pass:"$PASSWORD" \
    -CAcreateserial \
    -extfile "$SCRIPT_DIR/intermediate-ext.cnf" \
    -extensions v3_intermediate_ca \
    -out "$OUTPUT_DIR/intermediate-ca.cert.pem"

openssl pkcs12 \
    -export \
    -name flowerca-intermediate \
    -inkey "$OUTPUT_DIR/intermediate-ca.key.pem" \
    -passin pass:"$PASSWORD" \
    -in "$OUTPUT_DIR/intermediate-ca.cert.pem" \
    -certfile "$OUTPUT_DIR/root-ca.cert.pem" \
    -passout pass:"$PASSWORD" \
    -out "$OUTPUT_DIR/intermediate-ca.p12"

chmod 600 "$OUTPUT_DIR"/*.key.pem "$OUTPUT_DIR/intermediate-ca.p12"
chmod 644 "$OUTPUT_DIR"/*.cert.pem "$OUTPUT_DIR"/*.csr.pem

openssl verify \
    -CAfile "$OUTPUT_DIR/root-ca.cert.pem" \
    "$OUTPUT_DIR/intermediate-ca.cert.pem"

echo "Generated test CA material in $OUTPUT_DIR"
echo "PKCS#12 alias: flowerca-intermediate"
echo "Test password: $PASSWORD"
