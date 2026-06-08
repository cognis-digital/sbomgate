"""SBOMGATE command-line interface."""
from cognis_core import build_cli
from sbomgate.core import scan, TOOL_NAME, TOOL_VERSION

main = build_cli(
    tool_name=TOOL_NAME,
    tool_version=TOOL_VERSION,
    description="Continuous SBOM diff & vulnerability watch with maintainer-change tracking",
    scan_fn=scan,
)

if __name__ == "__main__":
    import sys
    sys.exit(main())
