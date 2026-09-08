import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

REPO = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = REPO / "scripts" / "package.py"

RELEASE_FILES = {
    "revana.exe",
    "revana_FFXi.dll",
    "revana_FFXiMain.dll",
    "revana_PolCoreContent.dll",
    "revana_patch.dll",
    "revana_hooks.dll",
    "rexruntime.dll",
    "rexgpu-xenos.dll",
}

BUILD_INFO = {
    "schema": 1,
    "product": "vana360",
    "version": "0.1.0",
    "title_commit": "1" * 40,
    "dirty": False,
    "sdk_commit": "2" * 40,
    "sdk_api_version": "0.10.0",
    "platform": "windows",
    "architecture": "x64",
    "configuration": "Release",
    "compiler": "Clang-22.1.0",
    "graphics_backend": "xenos",
    "supported_input_profile": "ffxi-ultimate-collection-usa-redump-63782",
}

BUILD_INFO_SUMMARY = (
    "vana360 v0.1.0 title=1111111111111111111111111111111111111111-clean "
    "sdk=2222222222222222222222222222222222222222 api=0.10.0 "
    "platform=windows arch=x64 config=Release compiler=Clang-22.1.0 "
    "backend=xenos input=ffxi-ultimate-collection-usa-redump-63782"
)


class PackageTests(unittest.TestCase):
    def _fixture(self):
        temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(temp.name)
        build = root / "build"
        output = root / "output"
        build.mkdir()
        for relative in RELEASE_FILES:
            (build / relative).write_bytes(relative.encode("ascii"))
        (build / "revana.exe").write_bytes(BUILD_INFO_SUMMARY.encode("ascii"))
        build_info_bytes = (json.dumps(BUILD_INFO, indent=2) + "\n").encode("ascii")
        (build / "revana-build-info.json").write_bytes(build_info_bytes)
        return temp, root, build, output

    def _run(self, build, output, *extra):
        return subprocess.run(
            [
                sys.executable,
                str(PACKAGE),
                "--build-dir",
                str(build),
                "--out-dir",
                str(output),
                *extra,
            ],
            cwd=REPO,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_windows_archive_has_only_release_allowlist(self):
        temp, root, build, output = self._fixture()
        with temp:
            (build / "unexpected.dll").write_bytes(b"extra")

            result = self._run(build, output)
            self.assertEqual(result.returncode, 0, result.stderr)
            archives = sorted(output.glob("vana360-v*-windows-x64.zip"))
            self.assertEqual(len(archives), 1)
            archive = archives[0]
            package_root = archive.name.removesuffix(".zip")
            expected_files = {
                f"{package_root}/{relative}" for relative in RELEASE_FILES
            }
            expected_files |= {
                f"{package_root}/LICENSE.txt",
                f"{package_root}/README.txt",
                f"{package_root}/build-info.json",
                f"{package_root}/licenses/REXGLUE-LICENSE.txt",
            }
            with zipfile.ZipFile(archive) as package:
                names = set(package.namelist())
                self.assertEqual(
                    names,
                    expected_files | {f"{package_root}/", f"{package_root}/game/"},
                )
                self.assertEqual(
                    package.read(f"{package_root}/build-info.json"),
                    (build / "revana-build-info.json").read_bytes(),
                )

    def test_archive_name_and_bytes_are_deterministic(self):
        temp, _, build, output = self._fixture()
        with temp:
            first = self._run(build, output)
            self.assertEqual(first.returncode, 0, first.stderr)
            archive = output / "vana360-v0.1.0-windows-x64.zip"
            self.assertTrue(archive.is_file())
            first_bytes = archive.read_bytes()
            for path in build.iterdir():
                path.touch()
            second = self._run(build, output)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(archive.read_bytes(), first_bytes)

    def test_missing_release_binary_fails(self):
        temp, _, build, output = self._fixture()
        with temp:
            (build / "revana.exe").unlink()
            result = self._run(build, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing Release binaries", result.stderr)

    def test_missing_build_info_fails(self):
        temp, _, build, output = self._fixture()
        with temp:
            (build / "revana-build-info.json").unlink()
            result = self._run(build, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("required file is missing", result.stderr)

    def test_private_build_info_field_fails(self):
        temp, _, build, output = self._fixture()
        with temp:
            build_info = dict(BUILD_INFO, private_asset_commit="3" * 40)
            (build / "revana-build-info.json").write_text(
                json.dumps(build_info), encoding="ascii"
            )
            result = self._run(build, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("build info fields are not exact", result.stderr)

    def test_duplicate_build_info_field_fails(self):
        temp, _, build, output = self._fixture()
        with temp:
            raw = (build / "revana-build-info.json").read_text(encoding="ascii")
            duplicate = raw.replace('"schema": 1,', '"schema": 1,\n  "schema": 1,')
            (build / "revana-build-info.json").write_text(duplicate, encoding="ascii")
            result = self._run(build, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not valid ASCII JSON", result.stderr)

    def test_package_target_must_match_build_info(self):
        temp, _, build, output = self._fixture()
        with temp:
            build_info = dict(BUILD_INFO, architecture="arm64")
            (build / "revana-build-info.json").write_text(
                json.dumps(build_info), encoding="ascii"
            )
            result = self._run(build, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("package target differs", result.stderr)

    def test_executable_must_match_build_info(self):
        temp, _, build, output = self._fixture()
        with temp:
            build_info = dict(BUILD_INFO, dirty=True)
            (build / "revana-build-info.json").write_text(
                json.dumps(build_info), encoding="ascii"
            )
            result = self._run(build, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("executable and build info differ", result.stderr)

    def test_reparse_entry_in_existing_stage_is_rejected(self):
        temp, root, build, output = self._fixture()
        with temp:
            first = self._run(build, output)
            self.assertEqual(first.returncode, 0, first.stderr)
            stage = output / "pkg" / "vana360-v0.1.0-windows-x64"
            external = root / "external"
            external.mkdir()
            marker = external / "keep.txt"
            marker.write_text("keep", encoding="ascii")
            try:
                (stage / "escape").symlink_to(external, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            second = self._run(build, output)
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("reparse point in staging tree", second.stderr)
            self.assertEqual(marker.read_text(encoding="ascii"), "keep")

    @unittest.skipUnless(os.name == "nt", "NTFS junction regression")
    def test_staging_root_junction_preserves_target(self):
        temp, _, build, output = self._fixture()
        with temp:
            package_dir = output / "pkg"
            package_dir.mkdir(parents=True)
            target = output / "existing-data"
            target.mkdir()
            marker = target / "keep.txt"
            marker.write_text("keep", encoding="ascii")
            stage = package_dir / "vana360-v0.1.0-windows-x64"
            junction = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(stage), str(target)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(junction.returncode, 0, junction.stderr)
            try:
                result = self._run(build, output)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("reparse point in staging tree", result.stderr)
                self.assertEqual(marker.read_text(encoding="ascii"), "keep")
            finally:
                # Unlink only the junction before temporary-directory cleanup.
                if stage.exists() and (
                    stage.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
                ):
                    stage.rmdir()


if __name__ == "__main__":
    unittest.main()
