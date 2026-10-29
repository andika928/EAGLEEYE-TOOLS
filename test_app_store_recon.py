import json
import unittest

from redteam_6tools import app_store_recon


class _FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, _limit):
        return self.payload


class AppStoreReconTests(unittest.TestCase):
    def test_parses_canonical_app_store_url(self):
        app_id, country = app_store_recon.parse_app_store_url(
            "https://apps.apple.com/us/app/vinted-pre-loved-marketplace/id632064380"
        )
        self.assertEqual(app_id, "632064380")
        self.assertEqual(country, "us")

    def test_rejects_non_apple_and_credential_urls(self):
        rejected = [
            "http://apps.apple.com/us/app/name/id632064380",
            "https://evil.example/us/app/name/id632064380",
            "https://apps.apple.com.evil.example/us/app/name/id632064380",
            "https://user@apps.apple.com/us/app/name/id632064380",
            "https://apps.apple.com:444/us/app/name/id632064380",
        ]
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(ValueError):
                app_store_recon.parse_app_store_url(value)

    def test_run_returns_metadata_with_honest_coverage(self):
        record = {
            "trackId": 632064380,
            "trackName": "Vinted: Pre-loved marketplace",
            "artistName": "Vinted Limited",
            "bundleId": "fr.vinted",
            "version": "26.40.0",
            "minimumOsVersion": "15.0",
            "fileSizeBytes": "359661568",
            "contentAdvisoryRating": "4+",
            "genres": ["Shopping"],
            "languageCodesISO2A": ["EN"],
            "supportedDevices": ["iPhone"],
            "currentVersionReleaseDate": "2026-10-14T00:00:00Z",
        }

        def opener(request, timeout):
            self.assertEqual(request.full_url.split("?")[0], "https://itunes.apple.com/lookup")
            self.assertEqual(timeout, 10)
            return _FakeResponse({"resultCount": 1, "results": [record]})

        result = app_store_recon.run(
            "https://apps.apple.com/us/app/vinted-pre-loved-marketplace/id632064380",
            opener=opener,
        )
        self.assertEqual(result["mode"], "passive_metadata_only")
        self.assertEqual(result["bundle_id"], "fr.vinted")
        self.assertTrue(any(item["status"] == "not_tested" for item in result["coverage"]))
        self.assertIn("No IPA was downloaded or inspected.", result["limitations"])


if __name__ == "__main__":
    unittest.main()
