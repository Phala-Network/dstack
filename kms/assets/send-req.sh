#!/bin/bash
CERT_FILE=${1}
KEY_FILE=${CERT_FILE%.*}.key
URL=https://localhost:8000/prpc/KMS.GetAppKey

if [ -z "$CERT_FILE" ]; then
    curl -s --cacert ca.cert ${URL}
else
    curl -s --cacert ca.cert --cert ${CERT_FILE} --key ${KEY_FILE} ${URL}
fi
