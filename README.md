# SBOMGATE — Continuous SBOM diff & vulnerability watch with maintainer-change tracking

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `blue-team`

[![PyPI](https://img.shields.io/pypi/v/cognis-sbomgate.svg)](https://pypi.org/project/cognis-sbomgate/)
[![CI](https://github.com/cognis-digital/sbomgate/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/sbomgate/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Continuous SBOM diff & vulnerability watch with maintainer-change tracking.

## Install

```bash
pip install cognis-sbomgate
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
sbomgate --version
sbomgate scan demos/                          # run against bundled demo
sbomgate scan demos/ --format sarif --out r.sarif --fail-on high
sbomgate mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-log4shell-class-incident/` — see [`SCENARIO.md`](demos/01-log4shell-class-incident/SCENARIO.md)
- `demos/02-supply-chain-maintainer-change/` — see [`SCENARIO.md`](demos/02-supply-chain-maintainer-change/SCENARIO.md)
- `demos/03-license-flip/` — see [`SCENARIO.md`](demos/03-license-flip/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
