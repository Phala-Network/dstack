#!/bin/bash

set -e

/bin/bash /etc/tproxy/prepare-conf.sh

exec "$@"
