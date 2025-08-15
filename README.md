# Naylence Advanced Security

A small collection of security components for the Naylence ecosystem. It provides pluggable encryption managers and certificate validation utilities that integrate with the Naylence FAME runtime via Python entry points.

## Features

- X25519 sealed-encryption manager
- Channel encryption manager
- Attachment certificate validator with CA service and local cache
- Plugin-based integration with the Naylence FAME runtime (via entry points)

## Requirements

- Python 3.12+
- Poetry for dependency management

## Install (local development)

Use Poetry to install dependencies and manage the virtual environment. The project declares a path dependency on `naylence-fame-runtime` at `../naylence-fame-runtime`. For local development, place that repository next to this one or update the dependency path in `pyproject.toml` to match your setup.

## Development

Use Black and Ruff for formatting and linting, Pyright for type checking, and Pytest for tests with coverage.

## Project layout

- `src/naylence/fame/security/encryption/sealed/` – X25519 encryption manager
- `src/naylence/fame/security/encryption/channel/` – Channel encryption manager
- `src/naylence/fame/security/cert/` – Certificate utilities (CA service, cache, validators)

## Runtime integration

This package exposes entry points consumed by the Naylence FAME runtime to discover and load security components (see `pyproject.toml`).

## Contributing

- Open an issue or pull request
- Ensure formatting, linting, type checking, and tests pass locally

## License

Business Source License (BSL). See `LICENSE` for full terms.