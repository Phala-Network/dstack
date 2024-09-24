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
