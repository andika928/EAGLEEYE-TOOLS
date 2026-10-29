import unittest
from unittest import mock

from redteam_6tools import ipatools_bridge


class IPAToolsBridgeTests(unittest.TestCase):
    def test_download_requires_authorization(self):
        with self.assertRaisesRegex(ValueError, "authorization"):
            ipatools_bridge.download(app_id="632064380", authorized=False)

    def test_download_rejects_ambiguous_and_bad_identifiers(self):
        with self.assertRaises(ValueError):
            ipatools_bridge.download(app_id="632064380", bundle_id="com.example.app", authorized=True)
        with self.assertRaises(ValueError):
            ipatools_bridge.download(app_id="../../bad", authorized=True)
        with self.assertRaises(ValueError):
            ipatools_bridge.download(bundle_id="../bad", authorized=True)

    def test_download_builds_fixed_argument_list_inside_download_directory(self):
        with mock.patch.object(ipatools_bridge, "DOWNLOAD_DIR", ipatools_bridge.ROOT), \
                mock.patch.object(ipatools_bridge, "_run") as run:
            run.return_value = {"ok": True, "output": "ignored", "zip_output": str(ipatools_bridge.ROOT / "x.zip")}
            result = ipatools_bridge.download(app_id="632064380", authorized=True, make_zip=True, analyze=False)
            args = run.call_args.args[0]
            timeout = run.call_args.kwargs["timeout"]
            self.assertEqual(args[0], "download")
            self.assertIn("--authorized", args)
            self.assertIn("--app-id", args)
            self.assertIn("632064380", args)
            self.assertIn("--zip", args)
            self.assertNotIn("--password", args)
            self.assertEqual(timeout, 46 * 60)
            self.assertTrue(result["artifact_url"].startswith("/api/mobile/artifacts/"))

    def test_resolve_artifact_blocks_traversal(self):
        with self.assertRaises(ValueError):
            ipatools_bridge.resolve_artifact("../secret.ipa")


if __name__ == "__main__":
    unittest.main()
