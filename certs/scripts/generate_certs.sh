#!/bin/bash
# scripts/generate_certs.sh
# Rulat O SINGURĂ DATĂ pentru setup inițial

set -e
CERTS_DIR="./certs"
mkdir -p $CERTS_DIR

echo "=== 1. Generare CA intern ==="
openssl genrsa -out $CERTS_DIR/ca.key 4096
openssl req -new -x509 -days 3650 \
    -key $CERTS_DIR/ca.key \
    -out $CERTS_DIR/ca.crt \
    -subj "/C=RO/O=FictiveBank/CN=NFC-Payment-CA"

echo "=== 2. Certificat Gateway (server) ==="
openssl genrsa -out $CERTS_DIR/gateway.key 2048
openssl req -new \
    -key $CERTS_DIR/gateway.key \
    -out $CERTS_DIR/gateway.csr \
    -subj "/C=RO/O=FictiveBank/CN=payment-gateway"
openssl x509 -req -days 365 \
    -in $CERTS_DIR/gateway.csr \
    -CA $CERTS_DIR/ca.crt \
    -CAkey $CERTS_DIR/ca.key \
    -CAcreateserial \
    -out $CERTS_DIR/gateway.crt

echo "=== 3. Certificat terminal POS de test ==="
openssl genrsa -out $CERTS_DIR/pos-buc-001.key 2048
openssl req -new \
    -key $CERTS_DIR/pos-buc-001.key \
    -out $CERTS_DIR/pos-buc-001.csr \
    -subj "/C=RO/O=FictiveBank/CN=POS-BUC-001"
openssl x509 -req -days 30 \
    -in $CERTS_DIR/pos-buc-001.csr \
    -CA $CERTS_DIR/ca.crt \
    -CAkey $CERTS_DIR/ca.key \
    -CAcreateserial \
    -out $CERTS_DIR/pos-buc-001.crt

echo "=== 4. Generare chei private pentru Issuing Banks ==="
openssl genrsa -out $CERTS_DIR/bank_bt_private.pem 2048
openssl genrsa -out $CERTS_DIR/bank_bcr_private.pem 2048
openssl genrsa -out $CERTS_DIR/bank_ing_private.pem 2048

echo "=== Certificate generate în $CERTS_DIR/ ==="
ls -la $CERTS_DIR/