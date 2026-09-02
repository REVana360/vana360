import pathlib
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
CI_WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"
CODEGEN_VERIFY = REPO / "scripts" / "verify-codegen-inputs.ps1"


class CiPrivacyTests(unittest.TestCase):
    def test_private_asset_revision_has_external_owner(self):
        ci = CI_WORKFLOW.read_text(encoding="ascii")
        self.assertIn(
            "https://github.com/REVana360/vana360-private-assets", ci
        )
        self.assertIn("ASSETS_COMMIT: ${{ secrets.ASSETS_COMMIT }}", ci)
        self.assertIn("GH_TOKEN: ${{ secrets.ASSETS_TOKEN }}", ci)
        self.assertIn("checkout --quiet --detach", ci)
        self.assertIn("$actualAssetCommit -cne $env:ASSETS_COMMIT", ci)
        self.assertNotIn("--branch main", ci)

    def test_public_output_does_not_emit_private_revision_or_root(self):
        ci = CI_WORKFLOW.read_text(encoding="ascii")
        verifier = CODEGEN_VERIFY.read_text(encoding="ascii")
        self.assertNotIn("Write-Output $env:ASSETS_COMMIT", ci)
        self.assertNotIn("root=$rootPath", verifier)
        self.assertIn("Verify package privacy", ci)


if __name__ == "__main__":
    unittest.main()
