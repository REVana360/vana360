"""Reject private revision markers in a Vana360 player archive."""

from __future__ import annotations

import argparse
import os
import pathlib
import zipfile


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=pathlib.Path)
    parser.add_argument("--forbidden-env", action="append", default=[])
    return parser.parse_args(argv)


def verify_archive(archive_path: pathlib.Path, markers: list[bytes]) -> None:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                name = info.filename.encode("utf-8")
                payload = archive.read(info) if not info.is_dir() else b""
                if any(marker in name or marker in payload for marker in markers):
                    raise SystemExit("error: private marker found in player archive")
    except (FileNotFoundError, zipfile.BadZipFile) as error:
        raise SystemExit("error: player archive is missing or invalid") from error


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    markers: list[bytes] = []
    for name in args.forbidden_env:
        value = os.environ.get(name, "")
        if not value:
            raise SystemExit("error: required private marker is unavailable")
        markers.append(value.encode("utf-8"))
    verify_archive(args.archive, markers)
    print("package-privacy: passed")


if __name__ == "__main__":
    main()
