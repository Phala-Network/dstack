#!/bin/bash

if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
else
    python3 -m venv .venv
    source .venv/bin/activate
    pip install requests eth_keys cryptography
fi
