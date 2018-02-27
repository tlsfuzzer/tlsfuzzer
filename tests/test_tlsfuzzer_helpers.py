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



from tlsfuzzer.helpers import sig_algs_to_ids


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
