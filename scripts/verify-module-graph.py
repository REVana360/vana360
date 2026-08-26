import pathlib
import sys
import tomllib


EXPECTED_MODULES = {
    "polcorecontent.xex",
    "ffxi.dll",
    "ffximain.dll",
    "patch.xex",
}


def beneath(path: str, root: str) -> bool:
    value = pathlib.PurePosixPath(path.replace("\\", "/"))
    return bool(value.parts) and value.parts[0].lower() == root


def main() -> int:
    repo = pathlib.Path(sys.argv[1]).resolve()
    manifests = sorted(repo.glob("*_manifest.toml"))
    if [path.name for path in manifests] != ["revana_manifest.toml"]:
        raise SystemExit("revana_manifest.toml must be the only title manifest")

    data = tomllib.loads(manifests[0].read_text(encoding="ascii"))
    if data.get("project", {}).get("name") != "revana":
        raise SystemExit("manifest project name must be revana")

    entrypoint = data.get("entrypoint", {})
    if pathlib.PurePosixPath(entrypoint.get("file_path", "")).name.lower() != "gameexeccontent0001.xex":
        raise SystemExit("manifest must have one GameExecContent0001 entrypoint")
    if not beneath(entrypoint.get("file_path", ""), "game"):
        raise SystemExit("entrypoint must read beneath game/")
    if not beneath(entrypoint.get("out_directory_path", ""), "generated"):
        raise SystemExit("entrypoint output must be beneath generated/")

    modules = data.get("modules", [])
    names = {module.get("guest_path", "").lower() for module in modules}
    if len(modules) != 4 or names != EXPECTED_MODULES:
        raise SystemExit("manifest companion module graph is not exact")
    for module in modules:
        if not beneath(module.get("file_path", ""), "game"):
            raise SystemExit("every module input must be beneath game/")
        if not beneath(module.get("out_directory_path", ""), "generated"):
            raise SystemExit("every module output must be beneath generated/")

    print("manifest-graph: passed entrypoints=1 modules=4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
