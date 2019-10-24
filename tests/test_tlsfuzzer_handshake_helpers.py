
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlsfuzzer.handshake_helpers import curve_name_to_hash_tls13

class TestCurveNameToHashTLS13(unittest.TestCase):
    def test_nist_p256(self):
        self.assertEqual("sha256", curve_name_to_hash_tls13("NIST256p"))

    def test_nist_p384(self):
        self.assertEqual("sha384", curve_name_to_hash_tls13("NIST384p"))

    def test_nist_p521(self):
        self.assertEqual("sha512", curve_name_to_hash_tls13("NIST521p"))

    def test_undefined_curve_name(self):
        with self.assertRaises(ValueError):
            curve_name_to_hash_tls13("P-256")
