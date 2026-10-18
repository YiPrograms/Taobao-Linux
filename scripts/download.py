#!/usr/bin/env python3
"""Download a file and verify its SHA-256 before adding it to the cache."""

import hashlib
import shutil
import sys
import urllib.request
from pathlib import Path


def download(url, destination, checksum):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    candidate = destination

    if not destination.exists():
        candidate = destination.with_suffix(destination.suffix + ".partial")
        print(f"Downloading {destination.name}", flush=True)
        request = urllib.request.Request(url, headers={"User-Agent": "TaobaoLinux/0.1"})

        with (
            urllib.request.urlopen(request, timeout=30) as response,
            candidate.open("wb") as output,
        ):
            shutil.copyfileobj(response, output)

    digest = hashlib.sha256()
    with candidate.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)

    if digest.hexdigest() != checksum:
        raise RuntimeError(f"Checksum mismatch: {candidate}")

    if candidate != destination:
        candidate.replace(destination)


if __name__ == "__main__":
    download(*sys.argv[1:])
