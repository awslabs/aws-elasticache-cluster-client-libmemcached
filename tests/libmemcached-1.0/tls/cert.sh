#!/bin/bash
OPENSSL_BIN="openssl"
#OPENSSL_BIN="/usr/local/opt/openssl@1.1/bin/openssl"

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

touch ca-db-index
echo 03 > ca-db-serial

# Certificate Authority
$OPENSSL_BIN req -nodes -x509 -newkey rsa:2048 -days 365 -keyout ca-key.pem -out ca-cert.pem -subj "/C=IL/L=TLV/O=AWS/OU=ElastiCache/CN=memcached-client-ca"

# Certificate
$OPENSSL_BIN req -nodes -new -newkey rsa:2048 -keyout memc-key.pem -out memc.csr -subj "/C=IL/L=TLV/O=AWS/OU=ElastiCache/CN=memcached-client"

# Sign Certificate
$OPENSSL_BIN ca -config $SCRIPT_DIR/ca.conf -days 365 -in memc.csr -out memc-cert.pem

mkdir -p $SCRIPT_DIR/certs/
cp memc-cert.pem $SCRIPT_DIR/certs/
cp memc-key.pem $SCRIPT_DIR/certs/