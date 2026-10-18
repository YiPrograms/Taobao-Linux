#!/usr/bin/env python3
"""Download a file and verify its SHA-256 before adding it to the cache."""

import hashlib
import subprocess
import sys
from pathlib import Path


def download(url, destination, checksum):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    candidate = destination

    try:
        if not destination.exists():
            candidate = destination.with_suffix(destination.suffix + ".partial")
            print(f"Downloading {destination.name}", flush=True)
            subprocess.run(
                [
                    "curl",
                    "--ipv4",
                    "--fail",
                    "--location",
                    "--silent",
                    "--show-error",
                    "--retry",
                    "4",
                    "--retry-all-errors",
                    "--retry-delay",
                    "3",
                    "--retry-max-time",
                    "600",
                    "--connect-timeout",
                    "20",
                    "--max-time",
                    "300",
                    "--user-agent",
                    "TaobaoLinux/0.1",
                    "--output",
                    str(candidate),
                    "--url",
                    url,
                ],
                check=True,
            )

        digest = hashlib.sha256()
        with candidate.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)

        if digest.hexdigest() != checksum:
            raise RuntimeError(f"Checksum mismatch: {candidate}")

        if candidate != destination:
            candidate.replace(destination)
    finally:
        if candidate != destination:
            candidate.unlink(missing_ok=True)


if __name__ == "__main__":
    download(*sys.argv[1:])
