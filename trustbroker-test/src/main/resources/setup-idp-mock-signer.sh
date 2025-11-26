#!/bin/bash

SUBJECT=${1:-/C=ch/O=trustbroker.swiss/OU=demo/CN=idp-mock-signer}
PKI_PASSPHRASE=${2:-testit}

export PKI_PASSPHRASE=testit
openssl req -x509 -text \
            -subj "$SUBJECT" \
            -days 3650 \
            -newkey rsa:2048 \
            -sha256 \
            -passout env:PKI_PASSPHRASE \
            -out test-idp-mock-keystore.pem \
            -keyout key.pem
cat key.pem >>test-idp-mock-keystore.pem
rm key.pem
