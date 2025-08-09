# Contributing to LanWatch

Thanks for your interest in contributing!

## How to contribute
- Fork the repo and create a feature branch from `master`.
- Use Conventional Commits (e.g., `feat:`, `fix:`) in your commit messages.
- For code changes:
  - Build locally to verify Dockerfile: `docker build -t lanwatch:dev .`
  - Optionally run locally: `docker run --rm --net host -e MQTT_HOST=127.0.0.1 -e SUBNETS="192.168.1.0/24" lanwatch:dev`
- Open a Pull Request with a clear description and screenshots/logs where relevant.

## Reporting issues
- Use the Bug Report template and include:
  - Expected vs. actual behavior
  - Steps to reproduce
  - Relevant logs (Docker logs, MQTT topics/payloads)
  - Network specifics (subnets/VLANs)

## Code style
- Python 3.11+.
- Prefer readable, explicit code. Add short docstrings for non-trivial functions.

## Security
- No port scanning by default; ARP only. For additional scanning or data sources, gate via opt-in settings.

## License
By contributing, you agree that your contributions will be licensed under the MIT License. 