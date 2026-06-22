<a name="top"></a>

<div align="center">



<img src="https://capsule-render.vercel.app/api?type=rect&color=0:6b46c1,100:2b6cb0&height=120&section=header&text=SBOMGATE&fontSize=48&fontColor=ffffff&fontAlignY=58" width="100%" alt="SBOMGATE"/>



# SBOMGATE



### Continuous SBOM diff & vulnerability watch with maintainer-change tracking



<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&duration=3500&pause=1000&color=6B46C1&center=true&vCenter=true&width=720&lines=Continuous+SBOM+diff++vulnerability+watch+with+maintainercha;Self-hostable+%C2%B7+MCP-native+%C2%B7+CI-ready+%C2%B7+polyglot" width="720"/>



[![PyPI](https://img.shields.io/pypi/v/cognis-sbomgate.svg?color=6b46c1)](https://pypi.org/project/cognis-sbomgate/) [![CI](https://github.com/cognis-digital/sbomgate/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/sbomgate/actions) [![License: COCL 1.0](https://img.shields.io/badge/License-COCL%201.0-2b6cb0.svg)](LICENSE) [![Suite](https://img.shields.io/badge/Cognis-Neural%20Suite-6b46c1.svg)](https://github.com/cognis-digital)



*Blue Team / Defense — detection, deception, and monitoring for small teams.*



</div>



```bash

pip install cognis-sbomgate

sbomgate scan .            # → prioritized findings in seconds

```



## Contents



- [Why sbomgate?](#why) · [Features](#features) · [Quick start](#quick-start) · [Example](#example) · [Demos](#demos) · [Architecture](#architecture) · [AI stack](#ai-stack) · [How it compares](#how-it-compares) · [Integrations](#integrations) · [Install anywhere](#install-anywhere) · [Related](#related) · [Contributing](#contributing)



## Usage — step by step

`sbomgate` diffs two SBOMs and/or matches an SBOM against a local advisory feed, then gates. Exit code is `1` when a finding meets/exceeds `--fail-on` (default `high`).

1. **Install**
   ```bash
   pip install sbomgate
   ```

2. **Scan the current SBOM** against a previous one and a local advisory feed:
   ```bash
   sbomgate scan new-sbom.json --old old-sbom.json --advisories advisories.json
   ```

3. **Run the focused subcommands** — `diff` two SBOMs, or `vulns`-match one:
   ```bash
   sbomgate diff old-sbom.json new-sbom.json
   sbomgate vulns new-sbom.json advisories.json
   ```

4. **Read JSON output** and tune the gate with `--fail-on {critical,high,medium,low}`:
   ```bash
   sbomgate scan new-sbom.json --advisories advisories.json --format json | jq '.gate'
   ```

   Or emit **SARIF 2.1.0** for GitHub code-scanning / SIEMs:
   ```bash
   sbomgate scan new-sbom.json --advisories advisories.json --format sarif > sbomgate.sarif
   ```

5. **Use in CI** — fail the build when a vuln or risky change crosses the threshold:
   ```bash
   sbomgate scan new-sbom.json --old old-sbom.json --advisories advisories.json \
     --fail-on high || exit 1
   ```

<a name="why"></a>

## Why sbomgate?



Continuous SBOM diff & vulnerability watch with maintainer-change tracking — without standing up heavyweight infrastructure.



`sbomgate` is single-purpose, scriptable, and self-hostable: point it at a target, get prioritized results in the format your workflow already speaks (table · JSON · SARIF), gate CI on it, and let agents drive it over MCP.



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="features"></a>

## Features



- ✅ Parse Sbom

- ✅ Load Sbom

- ✅ Diff Sboms

- ✅ Load Advisories

- ✅ Match Vulnerabilities

- ✅ Gate

- ✅ Runs on Linux/macOS/Windows · Docker · devcontainer

- ✅ Ports in Python, JavaScript, Go, and Rust (`ports/`)

- ✅ Live threat-intel enrichment: CISA-KEV (known-exploited) + EPSS (exploit probability), edge/air-gap-ready



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="threat-intel-feeds"></a>

## Threat-intel feeds — CISA-KEV + EPSS enrichment (edge / air-gap)

SBOMGATE ships a stdlib, **keyless** data-feed ingestion layer
(`sbomgate/datafeeds.py` + the bundled `data_feeds_2026.json` catalog) and wires
in the three feeds that genuinely sharpen an SBOM vulnerability gate:

| feed | source | what it adds |
|------|--------|--------------|
| `cisa-kev` | [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | the authoritative list of CVEs observed **actively exploited in the wild** — a drop-everything signal |
| `epss` | [FIRST EPSS](https://api.first.org/data/v1/epss) | per-CVE **probability of exploitation in the next 30 days** (0..1) for risk-ranking |
| `osv` | [OSV.dev](https://api.osv.dev/v1/query) | package@version → known vulns across PyPI/npm/Go/Maven/… |

These are **real public sources**; no endpoints are invented. The feed layer is
defensive / authorized-use only.

### What the enrichment does

`--enrich` folds KEV + EPSS into the vulnerability findings: any finding whose
advisory id resolves to a CVE on the **CISA-KEV** list is escalated to
`critical` and tagged `[KEV]`, and its **EPSS** score is attached
(`[KEV EPSS=0.9750]`). A wall of undifferentiated "high" findings becomes a
triage queue ordered by real-world exploitation likelihood.

```bash
# manage the feeds
sbomgate feeds list                       # show the 3 relevant feeds + cache age
sbomgate feeds update                      # fetch + cache cisa-kev, epss, osv
sbomgate feeds get cisa-kev --offline      # print the cached feed

# enrich a scan / vulns run
sbomgate vulns sbom.json advisories.json --enrich
sbomgate scan  new.json --advisories adv.json --enrich
```

Example (Log4Shell / Spring4Shell / Heartbleed are on CISA-KEV → escalated):

```
SEV  KIND           COMPONENT    DETAIL
!!   vulnerability  log4j-core   [CVE-2021-44228] [KEV EPSS=0.9750] Log4Shell: JNDI lookup RCE
!!   vulnerability  spring-core  [CVE-2022-22965] [KEV EPSS=0.9730] Spring4Shell RCE
!!   vulnerability  openssl      [CVE-2014-0160]  [KEV EPSS=0.9440] Heartbleed
!    vulnerability  requests     [GHSA-req-2015]  Credential leak (no CVE on KEV → stays high)
```

See `demos/11-feeds-kev-epss-enrichment/` (`run.sh` is fully offline).

### Edge / air-gap (offline + snapshot)

The feed cache lives at `$COGNIS_FEEDS_CACHE` (default `~/.cache/cognis-feeds`).
`--offline` serves **only** the cache and never touches the network — so the
gate keeps working on disconnected / military / edge gear:

```bash
sbomgate vulns sbom.json adv.json --enrich --offline
```

Sneakernet the feeds into a disconnected enclave:

```bash
# connected side — refresh + pack the cache
sbomgate feeds update
python -m sbomgate.datafeeds snapshot-export feeds.tar.gz

#   …carry feeds.tar.gz across the air gap…

# enclave side — rehydrate the cache, then run offline forever
python -m sbomgate.datafeeds snapshot-import feeds.tar.gz
sbomgate vulns sbom.json adv.json --enrich --offline
```

<div align="right"><a href="#top">↑ back to top</a></div>



<a name="quick-start"></a>

## Quick start



```bash

pip install cognis-sbomgate

sbomgate --version

sbomgate scan .                       # scan current project

sbomgate scan . --format json         # machine-readable

sbomgate scan . --format sarif        # SARIF 2.1.0 for code-scanning

sbomgate scan . --fail-on high        # CI gate (non-zero exit)

```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="example"></a>

## Example



```text

$ sbomgate scan .

  [HIGH    ] SBO-001  example finding             (./src/app.py)

  [MEDIUM  ] SBO-002  another signal              (./config.yaml)



  2 findings · risk score 5 · 38ms

```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="demos"></a>

## Demos — real-use-case scenarios

Every demo under [`demos/`](demos/) ships a `SCENARIO.md` plus SBOM/advisory
fixtures **in sbomgate's real input format**, and each one is exercised by the
test suite so the documented outcome stays true.

| Demo | What it shows | Outcome |
|---|---|---|
| [`01-basic`](demos/01-basic/) | CI build between two CycloneDX SBOMs: downgrade + maintainer takeover + new critical dep | gate FAILs |
| [`04-spdx-format-nodejs`](demos/04-spdx-format-nodejs/) | **SPDX 2.3** input from a Node.js build (lodash, minimist) | gate FAILs |
| [`05-transitive-critical`](demos/05-transitive-critical/) | A **downgrade re-introduces** a fixed critical (PyYAML CVE-2020-14343) | gate FAILs |
| [`06-clean-build-passes`](demos/06-clean-build-passes/) | Routine patch bumps, everything past its fix — the **negative control** | gate PASSes (exit 0) |
| [`07-ecosystem-mismatch`](demos/07-ecosystem-mismatch/) | Same name on PyPI **and** npm — ecosystem-scoped, no false positive | gate FAILs (1) |
| [`08-multi-ecosystem-monorepo`](demos/08-multi-ecosystem-monorepo/) | PyPI + npm + Maven + Go, Text4Shell + axios SSRF + maintainer change | gate FAILs |
| [`09-sarif-codescanning`](demos/09-sarif-codescanning/) | **SARIF 2.1.0** export wired into GitHub code-scanning | gate FAILs |
| [`10-version-range-and-gate`](demos/10-version-range-and-gate/) | `==` / `>=` / `<` / AND-range operator semantics + `--fail-on` tuning | gate FAILs |

```bash
# try one end to end:
python -m sbomgate scan demos/05-transitive-critical/sbom-new.json \
    --old demos/05-transitive-critical/sbom-old.json \
    --advisories demos/05-transitive-critical/advisories.json
```

> All CVE/GHSA identifiers in the demos are **real, published** advisories
> (except `10-version-range-and-gate`, which uses clearly-labelled synthetic
> ids to document matcher semantics).

<div align="right"><a href="#top">↑ back to top</a></div>

<a name="architecture"></a>

## Architecture



```mermaid
flowchart LR
  IN[target / manifest] --> P[sbomgate<br/>checks + rules]
  P --> OUT[findings (JSON / SARIF)]
```



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="ai-stack"></a>

## Use it from any AI stack



`sbomgate` is interoperable with every popular way of using AI:



- **MCP server** — `sbomgate mcp` (Claude Desktop, Cursor, Cognis.Studio, [uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet))

- **OpenAI-compatible / JSON** — pipe `sbomgate scan . --format json` into any agent or LLM

- **LangChain · CrewAI · AutoGen · LlamaIndex** — wrap the CLI/JSON as a tool in one line

- **CI / scripts** — exit codes + SARIF for non-AI pipelines



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="how-it-compares"></a>

## How it compares



| | **Cognis sbomgate** | anchore |

|---|:---:|:---:|

| Self-hostable, no account | ✅ | varies |

| Single command, zero config | ✅ | ⚠️ |

| JSON + SARIF for CI | ✅ | varies |

| MCP-native (AI agents) | ✅ | ❌ |

| Polyglot ports (JS/Go/Rust) | ✅ | ❌ |

| Open license | ✅ COCL | varies |



*Built in the spirit of **anchore/syft**, re-framed the Cognis way. Missing a credit? Open a PR.*



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="integrations"></a>

## Integrations



Pipes into your stack: **SARIF** for code-scanning, **JSON** for anything, an **MCP server** (`sbomgate mcp`) for AI agents, and a webhook forwarder for SIEM/Slack/Jira. See [`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md).



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="install-anywhere"></a>

## Install — every way, every platform



```bash

pip install "git+https://github.com/cognis-digital/sbomgate.git"    # pip (works today)

pipx install "git+https://github.com/cognis-digital/sbomgate.git"   # isolated CLI

uv tool install "git+https://github.com/cognis-digital/sbomgate.git" # uv

pip install cognis-sbomgate                                          # PyPI (when published)

docker run --rm ghcr.io/cognis-digital/sbomgate:latest --help        # Docker

brew install cognis-digital/tap/sbomgate                             # Homebrew tap

curl -fsSL https://raw.githubusercontent.com/cognis-digital/sbomgate/main/install.sh | sh

```



| Linux | macOS | Windows | Docker | Cloud |

|---|---|---|---|---|

| `scripts/setup-linux.sh` | `scripts/setup-macos.sh` | `scripts/setup-windows.ps1` | `docker run ghcr.io/cognis-digital/sbomgate` | [DEPLOY.md](docs/DEPLOY.md) (AWS/Azure/GCP/k8s) |



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="related"></a>

## Related Cognis tools



- [`sentrylog`](https://github.com/cognis-digital/sentrylog) — Single-file SIEM for small teams — Sigma rules + multi-source ingest

- [`edrgap`](https://github.com/cognis-digital/edrgap) — EDR coverage & bypass detector — reconciles MDM + EDR + AD inventories

- [`canarynet`](https://github.com/cognis-digital/canarynet) — Self-hosted canary token network — AWS keys, DNS, docs, web URLs

- [`phishforge`](https://github.com/cognis-digital/phishforge) — Open-source phishing simulation — campaigns, templates, training

- [`honeytrace`](https://github.com/cognis-digital/honeytrace) — Active-decoy network lure system — SSH, RDP, SMB, web honeypots



**Explore the suite →** [🗂️ all 170+ tools](https://github.com/cognis-digital/cognis-neural-suite) · [⭐ awesome-cognis](https://github.com/cognis-digital/awesome-cognis) · [🔗 cognis-sources](https://github.com/cognis-digital/cognis-sources) · [🤖 uncensored-fleet](https://github.com/cognis-digital/uncensored-fleet) · [🧠 engram](https://github.com/cognis-digital/engram)



<div align="right"><a href="#top">↑ back to top</a></div>



<a name="contributing"></a>

## Contributing



PRs, new rules, and demo scenarios are welcome under the collaboration-pull model — see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).



> ### ⭐ If `sbomgate` saved you time, **star it** — it genuinely helps others find it.



## Interoperability

`{}` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## License



Source-available under the **Cognis Open Collaboration License (COCL) v1.0** — free for personal, internal-evaluation, research, and educational use; **commercial / production use requires a license** (licensing@cognis.digital). See [LICENSE](LICENSE).



---



<div align="center"><sub><b><a href="https://cognis.digital">Cognis Digital</a></b> · one of 170+ tools in the <a href="https://github.com/cognis-digital/cognis-neural-suite">Cognis Neural Suite</a> · <i>Making Tomorrow Better Today</i></sub></div>


## Bundled vulnerability database

Ships `sbomgate/cognis_vulndb.jsonl.gz` — **262,351 real vulnerabilities** (OSV: PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet) with detailed metadata (CVE/GHSA aliases, ecosystem, severity/CVSS, affected packages, dates). Pure-stdlib offline loader `vulndb_local.VulnDB` (`count`/`by_cve`/`by_package`/`search`), air-gap ready. Refresh/extend via `datafeeds.py bulk`.
