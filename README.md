# Dstack

A platform for building and managing CVMs.


# Build & run

```
git clone https://github.com/Phala-Network/dstack
cd dstack

# Build TDX guest image
make -C mkguest dist

# Install the built image to teepod's lib directory
make -C mkguest dist DIST_DIR=~/.teepod/image/ubuntu-24.04

# Run teepod
cargo run -p teepod
```

Now the teepod is running on your local machine. Open browser and go to `http://localhost:8000` to see the dev console.

# Directory structure

```text
dstack/
    mkguest/                     Tools to make TDX guest image, currently based on Ubuntu 24.04
        initramfs/               Making initramfs image
            mod-tdx-guest/       The kernel module to support for extending RTMR
            config/scripts/kmfs  The boot script to set up disk encryption
        image/                   Building the guest image
        rootfs/                  Building the rootfs.iso
    kms/                         A prototype KMS server
    tappd/                       A service running in CVM to serve containers' key derivation and attestation requests.
    tdxctl/                      A CLI tool getting TDX quote, extending RTMR, generating cert for RA-TLS, etc.
    teepod/                      A service running in bare TDX host to manage CVMs
    tproxy/                      A reverse proxy to forward TLS connections to CVMs
    ra-rpc/                      RA-TLS support for pRPC
    ra-tls/                      RA-TLS support library
    tdx-attest/                  Guest library for getting TDX quote and extending RTMR
```
