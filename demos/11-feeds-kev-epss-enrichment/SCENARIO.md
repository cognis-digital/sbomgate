# Demo 11 — CISA-KEV + EPSS enrichment (edge / air-gap)

This SBOM pins four dependencies with known historical CVEs. A plain
`vulns` run flags all four as **high**. Folding in the real
[CISA Known Exploited Vulnerabilities](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
list and [FIRST EPSS](https://api.first.org/data/v1/epss) exploit-probability
scores changes the picture: the three CVEs that are *actively exploited in the
wild* (Log4Shell, Spring4Shell, Heartbleed) are escalated to **critical** and
tagged `[KEV EPSS=...]`, while the no-CVE advisory stays high.

## Offline (air-gap) run — uses the committed fixture cache, zero network

```sh
COGNIS_FEEDS_CACHE=tests/fixtures/feeds-cache \
  python -m sbomgate vulns \
    demos/11-feeds-kev-epss-enrichment/sbom.json \
    demos/11-feeds-kev-epss-enrichment/advisories.json \
    --enrich --offline --format table
```

Expected: `log4j-core`, `spring-core`, `openssl` -> **critical** `[KEV EPSS=…]`;
`requests` stays **high**; gate FAILs.

## Live run — pulls the real feeds, then caches them for next time

```sh
python -m sbomgate feeds update            # fetch + cache cisa-kev, epss, osv
python -m sbomgate vulns SBOM ADV --enrich # uses fresh cache
```

## Sneakernet to a disconnected enclave

```sh
python -m sbomgate.datafeeds snapshot-export feeds.tar.gz   # connected side
# ... carry feeds.tar.gz across the air gap ...
python -m sbomgate.datafeeds snapshot-import feeds.tar.gz    # enclave side
python -m sbomgate vulns SBOM ADV --enrich --offline
```
