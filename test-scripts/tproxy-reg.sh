#!/bin/bash
CERT_FILE=${1}
KEY_FILE=${CERT_FILE%.*}.key
CERT_DIR=../certs
URL=https://localhost:8010/prpc/Tproxy.RegisterCvm?json

D='{"wg_public_key": "4WyZldIHByffCulT674/n/ZLFH8jsfMZPkEnNOPaaW8="}'

if [ -z "$CERT_FILE" ]; then
    curl -s -d ${D} --cacert ${CERT_DIR}/ca.cert ${URL}
else
    curl -s -d "${D}" --cacert ${CERT_DIR}/ca.cert --cert ${CERT_FILE} --key ${KEY_FILE} ${URL}
fi
