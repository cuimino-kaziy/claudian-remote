"""Production Companion entry point for the authenticated loopback Bridge."""

import argparse
import asyncio
from pathlib import Path

from gateway.mac_companion.config import CompanionRuntimeConfig
from gateway.mac_companion.stream_pump import AsyncMacCompanion


def main() -> None:
    parser = argparse.ArgumentParser(description="Claudian Remote Mac Companion")
    parser.add_argument("--config", required=True, help="Path to device-local public configuration")
    args = parser.parse_args()
    config = CompanionRuntimeConfig.from_file(Path(args.config))
    config.validate()
    asyncio.run(AsyncMacCompanion.from_config(config).run_forever())


if __name__ == "__main__":
    main()
