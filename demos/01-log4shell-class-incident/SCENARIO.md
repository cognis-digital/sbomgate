# Scenario: Log4Shell-class incident — multiple critical CVEs introduced

A dependency update pulled in three vulnerable libraries.

## Expected findings

- SG-CVE-CRIT (log4j)
- SG-CVE-CRIT × 2 (jackson, snakeyaml — treated as critical workflow)

## Why this matters

This is the SBOM diff that should trigger an instant ticket.
