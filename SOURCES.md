# Sources

## Bundled offline data

- **OSV vulnerability DB** — `sbomgate/cognis_vulndb.jsonl.gz`, 262,351 real
  vulnerabilities consolidated from [OSV.dev](https://osv.dev) (PyPI, npm, Go,
  Maven, RubyGems, crates.io, NuGet). Read offline via `sbomgate.vulndb_local`
  and `sbomgate db ...`. License: OSV records are CC-BY 4.0 / per-source.
- **Keyless feed catalog** — `sbomgate/data_feeds_2026.json`, verified
  read-only HTTPS endpoints used to refresh threat-intel on the edge (CISA-KEV,
  FIRST EPSS, OSV query, NVD 2.0, GitHub GHSA). No API keys required.

<!-- cognis-2026-live-sources -->

## Live 2026 sources (auto-expanded)

_Always-current feeds, live web-search queries, and keyless APIs for real-time monitoring. Ingest at runtime with `livesearch.py`._

### Supply Chain
- **feed** · https://www.supplychaindive.com/feeds/news/
- **feed** · https://www.freightwaves.com/news/feed
- **live search** · `port congestion shipping delay 2026`
- **live search** · `tariff supply chain disruption`
- **live search** · `semiconductor export control`
- **api** · https://comtradeapi.un.org (UN Comtrade, free key)

### Ai
- **feed** · https://huggingface.co/blog/feed.xml
- **feed** · https://openai.com/news/rss.xml
- **feed** · https://www.anthropic.com/rss.xml
- **feed** · https://export.arxiv.org/rss/cs.AI
- **feed** · https://export.arxiv.org/rss/cs.LG
- **live search** · `frontier AI model release 2026`
- **live search** · `AI agent benchmark state of the art`
- **live search** · `open-weight LLM release`
- **live search** · `AI policy regulation 2026`
- **api** · http://export.arxiv.org/api/query (arXiv, free)
- **api** · https://api.github.com/search/repositories?q=stars (trending repos, free)
- **api** · https://hn.algolia.com/api (Hacker News, free)

### Cyber
- **feed** · https://www.cisa.gov/cybersecurity-advisories/all.xml
- **feed** · https://www.bleepingcomputer.com/feed/
- **feed** · https://thehackernews.com/feeds/posts/default
- **feed** · https://krebsonsecurity.com/feed/
- **feed** · https://www.darkreading.com/rss.xml
- **live search** · `actively exploited vulnerability 2026`
- **live search** · `ransomware campaign threat actor`
- **live search** · `zero-day disclosure CVE 2026`
- **api** · https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (KEV, free)
- **api** · https://services.nvd.nist.gov/rest/json/cves/2.0 (NVD CVE, free)
- **api** · https://otx.alienvault.com/api (threat pulses, free key)

