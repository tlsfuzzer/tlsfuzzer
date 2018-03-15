# Author: Hubert Kario, (c) Red Hat 2018
# Released under Gnu GPL v2.0, see LICENSE file for details
try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
    from mock import call
except ImportError:
    import unittest.mock as mock
    from unittest.mock import call



from tlsfuzzer.helpers import sig_algs_to_ids, key_share_gen
from tlslite.extensions import KeyShareEntry
from tlslite.constants import GroupName

class TestSigAlgsToIds(unittest.TestCase):
    def test_with_empty(self):
        ret = sig_algs_to_ids("")

        self.assertEqual(ret, [])

    def test_with_legacy(self):
        ret = sig_algs_to_ids("sha256+rsa")

        self.assertEqual(ret, [(4, 1)])

    def test_with_numerical(self):
        ret = sig_algs_to_ids("15+22")

        self.assertEqual(ret, [(15, 22)])

    def tes_with_mixed(self):
        ret = sig_algs_to_ids("15+rsa")

        self.assertEqual(ret, [(15, 1)])

    def test_with_signature_scheme(self):
        ret = sig_algs_to_ids("rsa_pss_pss_sha256")

        self.assertEqual(ret, [(8, 9)])

    def test_multiple_values(self):
        ret = sig_algs_to_ids("rsa_pss_pss_sha256 sha512+0")
        self.assertEqual(ret, [(8, 9), (6, 0)])


class TestKeyShareGen(unittest.TestCase):
    def test_with_ffdhe2048(self):
        ret = key_share_gen(GroupName.ffdhe2048)

        self.assertIsInstance(ret, KeyShareEntry)
        self.assertEqual(ret.group, GroupName.ffdhe2048)
        self.assertEqual(len(ret.key_exchange), 2048 // 8)

    def test_with_p256(self):
        ret = key_share_gen(GroupName.secp256r1)

        self.assertIsInstance(ret, KeyShareEntry)
        self.assertEqual(ret.group, GroupName.secp256r1)
        self.assertEqual(len(ret.key_exchange), 256 // 8 * 2 + 1)
