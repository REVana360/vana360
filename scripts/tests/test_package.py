import pathlib
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


class PackageTests(unittest.TestCase):
    def _fixture(self):
        temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(temp.name)
        build = root / "build"
        output = root / "output"
        build.mkdir()
        for relative in RELEASE_FILES:
            (build / relative).write_bytes(relative.encode("ascii"))
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
            expected_files = {f"{package_root}/{relative}" for relative in RELEASE_FILES}
            expected_files |= {
                f"{package_root}/LICENSE.txt",
                f"{package_root}/README.txt",
                f"{package_root}/licenses/REXGLUE-LICENSE.txt",
            }
            with zipfile.ZipFile(archive) as package:
                names = set(package.namelist())
                self.assertEqual(names, expected_files | {f"{package_root}/", f"{package_root}/game/"})
                self.assertNotIn(f"{package_root}/unexpected.dll", names)

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

    def test_non_windows_platform_is_rejected(self):
        temp, _, build, output = self._fixture()
        with temp:
            result = self._run(build, output, "--platform", "linux")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid choice", result.stderr)

    def test_non_x64_architecture_is_rejected(self):
        temp, _, build, output = self._fixture()
        with temp:
            result = self._run(build, output, "--arch", "arm64")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid choice", result.stderr)


if __name__ == "__main__":
    unittest.main()
