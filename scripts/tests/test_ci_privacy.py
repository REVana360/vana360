import pathlib
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
BUILD_WORKFLOW = REPO / ".github" / "workflows" / "build.yml"
CI_WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
CODEGEN_VERIFY = REPO / "scripts" / "verify-codegen-inputs.ps1"


class CiPrivacyTests(unittest.TestCase):
    def test_private_asset_revision_has_external_owner(self):
        build = BUILD_WORKFLOW.read_text(encoding="ascii")
        caller = CI_WORKFLOW.read_text(encoding="ascii")
        self.assertIn(
            "https://github.com/REVana360/vana360-private-assets", build
        )
        self.assertIn("ASSETS_COMMIT:\n        required: true", build)
        self.assertIn("ASSETS_COMMIT: ${{ secrets.ASSETS_COMMIT }}", caller)
        self.assertIn("checkout --quiet --detach", build)
        self.assertIn("$actualAssetCommit -cne $env:ASSETS_COMMIT", build)
        self.assertNotIn("--branch main", build)

    def test_public_output_does_not_emit_private_revision_or_root(self):
        build = BUILD_WORKFLOW.read_text(encoding="ascii")
        verifier = CODEGEN_VERIFY.read_text(encoding="ascii")
        self.assertNotIn("Write-Output $env:ASSETS_COMMIT", build)
        self.assertNotIn("root=$rootPath", verifier)
        self.assertIn("Verify package privacy", build)


if __name__ == "__main__":
    unittest.main()
