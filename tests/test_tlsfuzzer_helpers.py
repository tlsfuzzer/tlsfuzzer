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


from tlsfuzzer.helpers import sig_algs_to_ids, key_share_gen, psk_ext_gen, \
        flexible_getattr, psk_session_ext_gen
from tlsfuzzer.runner import ConnectionState
from tlslite.extensions import KeyShareEntry, PreSharedKeyExtension, \
        PskIdentity
from tlslite.constants import GroupName, CipherSuite
from tlslite.messages import NewSessionTicket

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


class TestPskExtGen(unittest.TestCase):
    def test_gen(self):
        config = [(b'test', b'secret', 'sha256'),
                  (b'example', b'secret', 'sha384')]

        ext = psk_ext_gen(config)

        self.assertIsInstance(ext, PreSharedKeyExtension)
        self.assertEqual(len(ext.identities), 2)
        self.assertEqual(ext.binders, [bytearray(32), bytearray(48)])
        self.assertEqual(ext.identities[0].identity, b'test')
        self.assertEqual(ext.identities[1].identity, b'example')

    def test_gen_without_hash_name(self):
        config = [(b'test', b'secret')]

        ext = psk_ext_gen(config)

        self.assertIsInstance(ext, PreSharedKeyExtension)
        self.assertEqual(len(ext.identities), 1)
        self.assertEqual(ext.binders, [bytearray(32)])
        self.assertEqual(ext.identities[0].identity, b'test')

    def test_gen_with_wrong_number_of_config_parameters(self):
        config = [(b'test', b'secret', 'sha256', 'extra')]

        with self.assertRaises(ValueError):
            psk_ext_gen(config)

    def test_gen_with_empty_name(self):
        config = [(b'', b'secret', 'sha256')]

        with self.assertRaises(ValueError):
            psk_ext_gen(config)

    def test_gen_with_wrong_hash_name(self):
        config = [(b'test', b'secret', 'sha512')]

        with self.assertRaises(ValueError):
            psk_ext_gen(config)


class TestPskSessionExtGen(unittest.TestCase):
    def test_gen(self):
        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_256_GCM_SHA384
        state.session_tickets = [NewSessionTicket().create(
            134, 0, bytearray(b'nonce'), bytearray(b'ticket value'), [])]
        state.session_tickets[0].time = 1214

        gen = psk_session_ext_gen()
        psk = gen(state)

        self.assertIsInstance(psk, PreSharedKeyExtension)
        self.assertEqual(len(psk.identities), 1)
        self.assertEqual(psk.binders, [bytearray(48)])
        self.assertEqual(psk.identities[0].identity, b'ticket value')

    def test_gen_with_psk_binders(self):
        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_256_GCM_SHA384
        state.session_tickets = [NewSessionTicket().create(
            134, 0, bytearray(b'nonce'), bytearray(b'ticket value'), [])]
        state.session_tickets[0].time = 1214

        config = [(b'test', b'secret', 'sha256'),
                  (b'example', b'secret', 'sha384')]

        ext = psk_session_ext_gen(config)(state)

        self.assertIsInstance(ext, PreSharedKeyExtension)
        self.assertEqual(len(ext.identities), 3)
        self.assertEqual(ext.binders, [bytearray(48), bytearray(32),
                                       bytearray(48)])
        self.assertEqual(ext.identities[0].identity, b'ticket value')
        self.assertEqual(ext.identities[1].identity, b'test')
        self.assertEqual(ext.identities[2].identity, b'example')

    def test_gen_with_session_ticket_missing(self):
        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_256_GCM_SHA384
        state.session_tickets = []

        gen = psk_session_ext_gen()
        with self.assertRaises(ValueError) as e:
            psk = gen(state)

        self.assertIn("No New Session Ticket", str(e.exception))


class TestFlexibleGetattr(unittest.TestCase):
    def test_with_number(self):
        self.assertEqual(12, flexible_getattr("12", None))

    def test_with_none(self):
        self.assertIsNone(flexible_getattr("none", GroupName))

    def test_with_name(self):
        self.assertEqual(24, flexible_getattr("secp384r1", GroupName))

    def test_with_invalid_name(self):
        with self.assertRaises(AttributeError):
            flexible_getattr("seccc", GroupName)
