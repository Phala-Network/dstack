#!/bin/sh
set -e
AESM_PATH=/opt/intel/sgx-aesm-service/aesm LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service --no-syslog
echo "Starting Gramine Sealing Key Provider"
make SGX=1 run-provider
