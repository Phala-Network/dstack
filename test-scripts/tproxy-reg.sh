#!/bin/bash
CERT_FILE=${1}
KEY_FILE=${CERT_FILE%.*}.key
URL=https://localhost:8010/prpc/Tproxy.RegisterCvm

if [ -z "$CERT_FILE" ]; then
    curl -s --cacert certs/ca.cert ${URL}
else
    curl -s --cacert certs/ca.cert --cert ${CERT_FILE} --key ${KEY_FILE} ${URL}
fi
