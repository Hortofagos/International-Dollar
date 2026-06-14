import unittest

from ind import address_generation
from ind import token as ind_token


class AddressGenerationTests(unittest.TestCase):
    def test_generate_keypair_returns_matching_address(self):
        address, private_key, public_key = address_generation.generate_keypair()

        self.assertTrue(private_key)
        self.assertTrue(public_key)
        self.assertEqual(ind_token.validate_address(address), address)
        self.assertTrue(ind_token.public_key_matches_address(public_key, address))

    def test_hash_func_preserves_legacy_list_output(self):
        generated = []

        address_generation.hash_func(generated)

        self.assertEqual(len(generated), 3)
        self.assertTrue(ind_token.public_key_matches_address(generated[2], generated[0]))


if __name__ == "__main__":
    unittest.main()
