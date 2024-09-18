# TDX Guest Image Builder

## Description
This project streamlines the process of building TDX (Trust Domain Extensions) guest images, enabling the creation of secure and isolated environments.

## Getting Started

### Prerequisites
- Ubuntu 24.04

### Setup
1. Prepare the build environment:
   ```
   sudo ./prepare_env.sh
   ```

### Building Components
You can build individual components or the entire project:

- Build the image:
  ```
  make image
  ```

- Build the rootfs:
  ```
  make rootfs
  ```

- Build the initramfs:
  ```
  make initramfs
  ```

- Build all components:
  ```
  make
  ```

### Testing
To test the built components, run the following command:
```
make run
```
