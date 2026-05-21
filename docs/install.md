# Installation

TinyPKI uses CMake and OpenSSL 3.x. The same build targets are used locally and
in CI.

## Requirements

- C11 compiler: GCC, Clang, or MSVC-compatible toolchain
- CMake 3.14 or newer
- OpenSSL 3.x development libraries

## Linux

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
```

## Windows MSYS2 UCRT64

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                  mingw-w64-ucrt-x86_64-cmake \
                  mingw-w64-ucrt-x86_64-ninja \
                  mingw-w64-ucrt-x86_64-openssl

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
```

## Verification

Run the same checks used for the release baseline:

```bash
ctest --test-dir build --output-on-failure
./build/test_all
```

On Windows PowerShell with the default generator, the executable may be
`.\build\test_all.exe`.

## Demo Targets

```bash
cmake --build build --target sm2_test_cert_flow -j 4
./build/sm2_test_cert_flow

cmake --build build --target sm2_test_merkle_flow -j 4
./build/sm2_test_merkle_flow
```

On Windows PowerShell, use the `.exe` suffix when needed.
