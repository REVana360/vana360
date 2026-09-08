"""Build a Vana360 Windows x64 release archive from an explicit allowlist."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import stat
import zipfile


REPO = pathlib.Path(__file__).resolve().parent.parent
PACKAGE_NAME = "vana360"
BUILD_INFO_NAME = "revana-build-info.json"
PACKAGE_BUILD_INFO_NAME = "build-info.json"
PACKAGE_PLATFORM = "windows"
PACKAGE_ARCHITECTURE = "x64"

# These are the Release outputs of the `revana` host and its generated module
# targets.  Runtime-loaded SDK libraries are listed explicitly as well.
RELEASE_FILES = (
    "revana.exe",
    "revana_FFXi.dll",
    "revana_FFXiMain.dll",
    "revana_PolCoreContent.dll",
    "revana_patch.dll",
    "revana_hooks.dll",
    "rexruntime.dll",
    "rexgpu-xenos.dll",
)

BUILD_INFO_FIELDS = {
    "schema",
    "product",
    "version",
    "title_commit",
    "dirty",
    "sdk_commit",
    "sdk_api_version",
    "platform",
    "architecture",
    "configuration",
    "compiler",
    "graphics_backend",
    "supported_input_profile",
}

FORBIDDEN_INPUT_SUFFIXES = {
    ".dat",
    ".iso",
    ".log",
    ".sve",
    ".trace",
    ".xex",
    ".xexp",
}


def _build_info_matches(build_info: dict, field: str, pattern: str) -> bool:
    value = build_info[field]
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate build info field")
        result[key] = value
    return result


def read_build_info(build_dir: pathlib.Path) -> tuple[dict, bytes]:
    """Read and validate the build-owned public information record."""

    path = build_dir / BUILD_INFO_NAME
    _regular_file(path, BUILD_INFO_NAME)
    raw = path.read_bytes()
    try:
        build_info = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit("error: build info is not valid ASCII JSON") from error

    if not isinstance(build_info, dict) or set(build_info) != BUILD_INFO_FIELDS:
        raise SystemExit("error: build info fields are not exact")
    if build_info["schema"] != 1 or build_info["product"] != PACKAGE_NAME:
        raise SystemExit("error: unsupported build info schema")
    if not _build_info_matches(build_info, "version", r"\d+\.\d+\.\d+"):
        raise SystemExit("error: invalid build version")
    if not _build_info_matches(build_info, "title_commit", r"[0-9a-f]{40}"):
        raise SystemExit("error: invalid title commit")
    if not isinstance(build_info["dirty"], bool):
        raise SystemExit("error: invalid title source state")
    if not _build_info_matches(build_info, "sdk_commit", r"[0-9a-f]{40}"):
        raise SystemExit("error: invalid SDK commit")
    if not _build_info_matches(build_info, "sdk_api_version", r"\d+\.\d+\.\d+"):
        raise SystemExit("error: invalid SDK API version")
    if (
        build_info["platform"] != PACKAGE_PLATFORM
        or build_info["architecture"] != PACKAGE_ARCHITECTURE
    ):
        raise SystemExit("error: package target differs from build info")
    for field in ("configuration", "compiler"):
        if not _build_info_matches(build_info, field, r"[A-Za-z0-9_.+-]+"):
            raise SystemExit(f"error: invalid {field}")
    if build_info["graphics_backend"] != "xenos":
        raise SystemExit("error: unsupported graphics backend")
    if not _build_info_matches(
        build_info, "supported_input_profile", r"[a-z0-9]+(?:-[a-z0-9]+)+"
    ):
        raise SystemExit("error: invalid supported input profile")
    return build_info, raw


def build_info_summary(build_info: dict) -> str:
    source_state = "dirty" if build_info["dirty"] else "clean"
    return (
        f"vana360 v{build_info['version']} "
        f"title={build_info['title_commit']}-{source_state} "
        f"sdk={build_info['sdk_commit']} "
        f"api={build_info['sdk_api_version']} "
        f"platform={build_info['platform']} "
        f"arch={build_info['architecture']} "
        f"config={build_info['configuration']} "
        f"compiler={build_info['compiler']} "
        f"backend={build_info['graphics_backend']} "
        f"input={build_info['supported_input_profile']}"
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-dir",
        type=pathlib.Path,
        default=REPO / "build" / "win-amd64-title-release",
        help="Release build directory",
    )
    parser.add_argument(
        "--out-dir",
        type=pathlib.Path,
        default=REPO / "out",
        help="directory receiving the archive and staging tree",
    )
    return parser.parse_args(argv)


def _is_reparse_point(path: pathlib.Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, FileNotFoundError, OSError):
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _regular_file(path: pathlib.Path, label: str) -> None:
    if _is_reparse_point(path):
        raise SystemExit(f"error: reparse point is not allowed: {label}")
    if not path.is_file():
        raise SystemExit(f"error: required file is missing: {label}")


def _copy_regular_file(
    source: pathlib.Path, destination: pathlib.Path, label: str
) -> None:
    _regular_file(source, label)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _remove_regular_tree(path: pathlib.Path) -> None:
    if _is_reparse_point(path):
        raise SystemExit(f"error: reparse point in staging tree: {path}")
    for child in path.iterdir():
        if _is_reparse_point(child):
            raise SystemExit(f"error: reparse point in staging tree: {child}")
        if child.is_dir():
            _remove_regular_tree(child)
        elif child.is_file():
            child.unlink()
        else:
            raise SystemExit(f"error: unsupported staging entry: {child}")
    path.rmdir()


def _safe_stage(out_dir: pathlib.Path, name: str) -> pathlib.Path:
    out_root = out_dir.resolve()
    if _is_reparse_point(out_dir) or (out_dir.exists() and not out_dir.is_dir()):
        raise SystemExit(
            f"error: output directory is not a regular directory: {out_dir}"
        )
    package_dir = out_dir / "pkg"
    if _is_reparse_point(package_dir) or (
        package_dir.exists() and not package_dir.is_dir()
    ):
        raise SystemExit(
            f"error: package staging directory is not a regular directory: {package_dir}"
        )
    if package_dir.exists() and package_dir.resolve().parent != out_root:
        raise SystemExit(
            f"error: package staging directory escapes output directory: {package_dir}"
        )
    package_dir.mkdir(parents=True, exist_ok=True)
    stage = out_dir / "pkg" / name
    if _is_reparse_point(stage):
        raise SystemExit(f"error: reparse point in staging tree: {stage}")
    if out_root not in stage.resolve().parents:
        raise SystemExit(f"error: staging path escapes output directory: {stage}")
    if stage.exists():
        if not stage.is_dir():
            raise SystemExit(f"error: staging path is not a directory: {stage}")
        if out_root not in stage.resolve().parents:
            raise SystemExit(f"error: staging path escapes output directory: {stage}")
        _remove_regular_tree(stage)
    stage.mkdir()
    return stage


def _write_zip(archive_path: pathlib.Path, stage: pathlib.Path, name: str) -> None:
    entries = [pathlib.PurePosixPath(relative) for relative in RELEASE_FILES]
    entries.extend(
        (
            pathlib.PurePosixPath(PACKAGE_BUILD_INFO_NAME),
            pathlib.PurePosixPath("LICENSE.txt"),
            pathlib.PurePosixPath("README.txt"),
            pathlib.PurePosixPath("licenses/REXGLUE-LICENSE.txt"),
        )
    )
    entries.sort()

    with zipfile.ZipFile(
        archive_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        root_info = zipfile.ZipInfo(f"{name}/")
        root_info.date_time = (1980, 1, 1, 0, 0, 0)
        root_info.create_system = 0
        root_info.external_attr = (stat.S_IFDIR | 0o755) << 16
        archive.writestr(root_info, b"")

        for relative in entries:
            source = stage / pathlib.Path(*relative.parts)
            _regular_file(source, str(relative))
            info = zipfile.ZipInfo(f"{name}/{relative.as_posix()}")
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(
                info,
                source.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )

        game_info = zipfile.ZipInfo(f"{name}/game/")
        game_info.date_time = (1980, 1, 1, 0, 0, 0)
        game_info.create_system = 0
        game_info.external_attr = (stat.S_IFDIR | 0o755) << 16
        archive.writestr(game_info, b"")


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if _is_reparse_point(args.build_dir) or not args.build_dir.is_dir():
        raise SystemExit(
            f"error: Release build directory is missing or a reparse point: {args.build_dir}"
        )
    build_dir = args.build_dir.resolve()

    build_info, build_info_bytes = read_build_info(build_dir)
    name = f"{PACKAGE_NAME}-v{build_info['version']}-{PACKAGE_PLATFORM}-{PACKAGE_ARCHITECTURE}"

    stage = _safe_stage(args.out_dir, name)
    missing: list[str] = []
    for relative in RELEASE_FILES:
        source = build_dir / relative
        if _is_reparse_point(source) or not source.is_file():
            missing.append(str(source))
            continue
        _copy_regular_file(source, stage / relative, relative)
    if missing:
        raise SystemExit("error: missing Release binaries:\n  " + "\n  ".join(missing))
    executable = build_dir / "revana.exe"
    if build_info_summary(build_info).encode("ascii") not in executable.read_bytes():
        raise SystemExit("error: executable and build info differ")

    _copy_regular_file(
        REPO / "scripts" / "packaging" / "README.txt",
        stage / "README.txt",
        "README.txt",
    )
    _copy_regular_file(REPO / "LICENSE", stage / "LICENSE.txt", "LICENSE")
    _copy_regular_file(
        REPO / "REXGLUE-LICENSE.txt",
        stage / "licenses" / "REXGLUE-LICENSE.txt",
        "licenses/REXGLUE-LICENSE.txt",
    )
    (stage / PACKAGE_BUILD_INFO_NAME).write_bytes(build_info_bytes)
    (stage / "game").mkdir()

    for staged in stage.rglob("*"):
        if _is_reparse_point(staged):
            raise SystemExit(f"error: reparse point staged: {staged}")
        if staged.is_file() and staged.suffix.lower() in FORBIDDEN_INPUT_SUFFIXES:
            raise SystemExit(f"error: forbidden file staged: {staged}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    archive_path = args.out_dir / f"{name}.zip"
    if _is_reparse_point(archive_path):
        raise SystemExit(f"error: archive path is a reparse point: {archive_path}")
    _write_zip(archive_path, stage, name)
    print(f"packaged: {archive_path}")


if __name__ == "__main__":
    main()
