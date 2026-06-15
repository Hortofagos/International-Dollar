import unittest

from ind import address_generation, update_manifest


def signed_manifest(sequence=1, channel="operator-canary"):
    _address, private_key, public_key = address_generation.generate_legacy_keypair()
    manifest = {
        "type": update_manifest.UPDATE_MANIFEST_TYPE,
        "version": 1,
        "channel": channel,
        "release_id": f"release-{sequence}",
        "sequence": sequence,
        "published_at": 1_700_000_000,
        "min_supported_sequence": 0,
        "requires_restart": True,
        "artifacts": [
            {
                "platform": "source",
                "url": "https://example.invalid/release.zip",
                "sha3_256": "a" * 64,
                "size_bytes": 123,
            }
        ],
    }
    return (
        update_manifest.sign_update_manifest(manifest, private_key, public_key),
        private_key,
        public_key,
    )


class OperatorUpdateTests(unittest.TestCase):
    def test_promotion_requires_canary_release_identity_match(self):
        canary, private_key, public_key = signed_manifest(sequence=11)
        promotion = update_manifest.sign_operator_promotion(
            update_manifest.make_operator_promotion(canary, "b" * 64),
            private_key,
            public_key,
        )
        self.assertTrue(update_manifest.verify_operator_promotion(promotion, [public_key], canary))

        other = dict(canary)
        other["release_id"] = "different-release"
        with self.assertRaises(update_manifest.UpdateManifestError):
            update_manifest.verify_operator_promotion(promotion, [public_key], other)

    def test_promotion_rejects_untrusted_signing_key(self):
        canary, private_key, public_key = signed_manifest(sequence=12)
        promotion = update_manifest.sign_operator_promotion(
            update_manifest.make_operator_promotion(canary, "c" * 64),
            private_key,
            public_key,
        )
        with self.assertRaises(update_manifest.UpdateManifestError):
            update_manifest.verify_operator_promotion(promotion, ["untrusted"], canary)


if __name__ == "__main__":
    unittest.main()
