import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile


REPO = pathlib.Path(__file__).resolve().parents[2]
VERIFY = REPO / "scripts" / "verify-package-privacy.py"


class PackagePrivacyTests(unittest.TestCase):
    def _archive(self, payload: bytes):
        temp = tempfile.TemporaryDirectory()
        archive_path = pathlib.Path(temp.name) / "player.zip"
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("vana360/revana.exe", payload)
        return temp, archive_path

    def _run(self, archive: pathlib.Path, marker: str):
        environment = dict(os.environ, TEST_PRIVATE_MARKER=marker)
        return subprocess.run(
            [
                sys.executable,
                str(VERIFY),
                "--archive",
                str(archive),
                "--forbidden-env",
                "TEST_PRIVATE_MARKER",
            ],
            cwd=REPO,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_clean_archive_passes(self):
        temp, archive = self._archive(b"public build")
        with temp:
            result = self._run(archive, "3" * 40)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_private_revision_in_payload_fails(self):
        marker = b"3" * 40
        temp, archive = self._archive(b"prefix" + marker + b"suffix")
        with temp:
            result = self._run(archive, marker.decode("ascii"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private marker", result.stderr)

    def test_private_revision_in_name_fails(self):
        marker = b"3" * 40
        temp = tempfile.TemporaryDirectory()
        with temp:
            archive_path = pathlib.Path(temp.name) / "player.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr(f"vana360/{marker.decode('ascii')}.txt", b"")
            result = self._run(archive_path, marker.decode("ascii"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private marker", result.stderr)


if __name__ == "__main__":
    unittest.main()
