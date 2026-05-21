# Contributing

Thank you for improving TinyPKI. This project is a security-sensitive C library,
so contributions should be small, reviewable, and backed by tests or clear
verification steps.

## Development Workflow

1. Create a focused branch from the latest `main`.
2. Keep each pull request scoped to one feature, fix, or documentation update.
3. Prefer high-level public PKI APIs in examples and tests. Internal Merkle,
   authentication, and service helpers should not be promoted as integration
   entry points.
4. Do not commit generated build directories, benchmark output, local IDE
   metadata, credentials, tokens, private keys, or temporary files.
5. Use technical commit messages that describe the change, for example
   `security: harden evidence decoding bounds`.

## Required Checks

Run the relevant checks before opening a pull request:

```powershell
powershell -ExecutionPolicy Bypass -File tools\check_format.ps1
cmake -S . -B build
cmake --build build -j 1
ctest --test-dir build --output-on-failure
.\build\test_all.exe
```

On Linux or CI-style environments:

```bash
bash tools/check_format.sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j 4
ctest --test-dir build --output-on-failure
./build/test_all
```

For changes touching benchmarks or evidence formats, also run the affected
benchmark target and include the command in the pull request description.

## Code Style

- The C code is formatted with clang-format 18 through `tools/format.ps1` or
  `tools/format.sh`.
- Keep public headers concise and document integration-facing behavior.
- Keep internal helpers inside the relevant `src/` module boundary unless there
  is a clear reason to make them public.
- Prefer explicit length checks, fixed-size buffer validation, and domain
  separation for serialized or hashed data.
- Clear sensitive outputs on failure paths and avoid exposing low-level crypto
  details through high-level APIs.

## Pull Request Checklist

Before requesting review, confirm:

- The change matches the pull request title and description.
- New behavior has focused tests, or the reason for no test is documented.
- Format checks pass.
- `ctest` passes.
- Security-sensitive behavior is described clearly enough for review.
- Documentation and examples still match the implemented behavior.

## Reporting Security Issues

Do not disclose exploitable issues in public issues or pull requests before a
fix or mitigation is available. Follow the process in [SECURITY.md](SECURITY.md)
for vulnerability reports.
