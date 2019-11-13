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
        flexible_getattr, psk_session_ext_gen, key_share_ext_gen, \
        uniqueness_check, AutoEmptyExtension, protocol_name_to_tuple, \
        client_cert_types_to_ids, ext_names_to_ids, expected_ext_parser, \
        dict_update_non_present
from tlsfuzzer.runner import ConnectionState
from tlslite.extensions import KeyShareEntry, PreSharedKeyExtension, \
        PskIdentity, ClientKeyShareExtension
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


class TestExtNamesToIds(unittest.TestCase):
    def test_with_empty(self):
        ret = ext_names_to_ids("")

        self.assertEqual(ret, [])

    def test_with_name(self):
        ret = ext_names_to_ids("server_name")

        self.assertEqual(ret, [0])

    def test_with_id(self):
        ret = ext_names_to_ids("0")

        self.assertEqual(ret, [0])

    def test_with_two_ids(self):
        ret = ext_names_to_ids("0 1")

        self.assertEqual(ret, [0, 1])

    def test_with_id_and_name(self):
        ret = ext_names_to_ids("0 heartbeat")

        self.assertEqual(ret, [0, 15])

    def test_with_unrecognised_name(self):
        with self.assertRaises(AttributeError):
            ext_names_to_ids("foobar")


class TestClientCertTypesToIds(unittest.TestCase):
    def test_with_empty(self):
        ret = client_cert_types_to_ids("")

        self.assertEqual(ret, [])

    def test_with_one(self):
        ret = client_cert_types_to_ids("rsa_sign")

        self.assertEqual(ret, [1])

    def test_with_two(self):
        ret = client_cert_types_to_ids("rsa_sign ecdsa_sign")

        self.assertEqual(ret, [1, 64])

    def test_with_mixed(self):
        ret = client_cert_types_to_ids("1 ecdsa_sign")

        self.assertEqual(ret, [1, 64])

    def test_with_malformed_integer(self):
        with self.assertRaises(AttributeError):
            client_cert_types_to_ids("1/23 ecdsa_sign")

    def test_with_unknown_name(self):
        with self.assertRaises(AttributeError):
            client_cert_types_to_ids("ed448_sign")


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


class TestKeyShareExtGen(unittest.TestCase):
    def test_with_group(self):
        gen = key_share_ext_gen([GroupName.secp256r1])

        ext = gen(None)

        self.assertIsInstance(ext, ClientKeyShareExtension)
        self.assertEqual(len(ext.client_shares), 1)
        self.assertEqual(ext.client_shares[0].group, GroupName.secp256r1)

    def test_with_entry(self):
        entry = KeyShareEntry().create(1313, bytearray(b'something'))
        gen = key_share_ext_gen([entry])

        ext = gen(None)

        self.assertIsInstance(ext, ClientKeyShareExtension)
        self.assertEqual(len(ext.client_shares), 1)
        self.assertEqual(ext.client_shares[0].group, 1313)
        self.assertEqual(ext.client_shares[0].key_exchange, b'something')


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


class TestUniquenessCheck(unittest.TestCase):
    def test_with_empty(self):
        self.assertEqual([], uniqueness_check({}, 0))

    def test_with_ints(self):
        self.assertEqual([], uniqueness_check({'ints': [1, 2, 3, 4]}, 4))

    def test_with_duplicated_ints(self):
        self.assertEqual(["Duplicated entries in 'ints'."],
                         uniqueness_check({'ints': [1, 2, 3, 1]}, 4))

    def test_with_mismatched_count(self):
        self.assertEqual(["Unexpected number of values in 'ints'. Expected: "
                          "4, got: 3."],
                         uniqueness_check({'ints': [1, 2, 3]}, 4))

    def test_with_bytearrays(self):
        self.assertEqual(
            [],
            uniqueness_check({'bytearrays':
                             [bytearray(b'a'), bytearray(b'b')]}, 2))

    def test_with_duplicated_bytearrays(self):
        self.assertEqual(
            ["Duplicated entries in 'bytearrays'."],
            uniqueness_check({'bytearrays':
                             [bytearray(b'a'), bytearray(b'a')]}, 2))


class TestAutoEmptyExtension(unittest.TestCase):
    def test_equality(self):
        var1 = AutoEmptyExtension()
        var2 = AutoEmptyExtension()

        self.assertEqual(var1, var2)

    def test_identity(self):
        var1 = AutoEmptyExtension()
        var2 = AutoEmptyExtension()

        self.assertIs(var1, var2)

    def test__init__(self):
        var = AutoEmptyExtension()

        self.assertIsInstance(var, AutoEmptyExtension)


class TestProtocolNameToTuple(unittest.TestCase):
    def test_sslv2(self):
        self.assertEqual((0, 2), protocol_name_to_tuple("SSLv2"))

    def test_ssl2(self):
        self.assertEqual((0, 2), protocol_name_to_tuple("SSL2"))

    def test_sslv3(self):
        self.assertEqual((3, 0), protocol_name_to_tuple("SSLv3"))

    def test_ssl3(self):
        self.assertEqual((3, 0), protocol_name_to_tuple("SSL3"))

    def test_tlsv10(self):
        self.assertEqual((3, 1), protocol_name_to_tuple("TLSv1.0"))

    def test_tls10(self):
        self.assertEqual((3, 1), protocol_name_to_tuple("TLS1.0"))

    def test_tlsv11(self):
        self.assertEqual((3, 2), protocol_name_to_tuple("TLSv1.1"))

    def test_tls11(self):
        self.assertEqual((3, 2), protocol_name_to_tuple("TLS1.1"))

    def test_tlsv12(self):
        self.assertEqual((3, 3), protocol_name_to_tuple("TLSv1.2"))

    def test_tls12(self):
        self.assertEqual((3, 3), protocol_name_to_tuple("TLS1.2"))

    def test_tlsv13(self):
        self.assertEqual((3, 4), protocol_name_to_tuple("TLSv1.3"))

    def test_tls13(self):
        self.assertEqual((3, 4), protocol_name_to_tuple("TLS1.3"))

    def test_unknown(self):
        with self.assertRaises(ValueError):
            protocol_name_to_tuple("SSL3.1")


class TestExpectedExtParser(unittest.TestCase):
    def setUp(self):
        self.exp = {'CH': [],
                    'SH': [],
                    'EE': [],
                    'CT': [],
                    'CR': [],
                    'NST': [],
                    'HRR': []}

    def test_empty(self):
        ret = expected_ext_parser("")

        self.assertEqual(ret, self.exp)

    def test_server_name_in_CH(self):
        ret = expected_ext_parser("server_name:CH")

        self.exp['CH'] = [0]

        self.assertEqual(ret, self.exp)

    def test_numeric_id_in_CH_and_SH(self):
        ret = expected_ext_parser("22:CH:SH")

        self.exp['CH'] = [22]
        self.exp['SH'] = [22]

        self.assertEqual(ret, self.exp)

    def test_two_extensions_in_CH(self):
        ret = expected_ext_parser("server_name:CH 22:CH")

        self.exp['CH'] = [0, 22]

        self.assertEqual(ret, self.exp)

    def test_missing_colon(self):
        with self.assertRaises(ValueError):
            expected_ext_parser("server_name")

    def test_missing_msg_name(self):
        with self.assertRaises(ValueError):
            expected_ext_parser("server_name:CH:")

    def test_with_invalid_name(self):
        with self.assertRaises(AttributeError):
            expected_ext_parser("blahblablah:CH")

    def test_with_invalid_message_id(self):
        with self.assertRaises(ValueError):
            expected_ext_parser("server_name:ClientHello")


class TestDictUpdateNotPresent(unittest.TestCase):
    def test_none_dict_none_keys(self):
        ret = dict_update_non_present(None, None)
        self.assertIsNone(ret)

    def test_dict_with_none_keys(self):
        ref = object()
        ret = dict_update_non_present(ref, None)

        self.assertIs(ref, ret)

    def test_none_dict_def_keys(self):
        ret = dict_update_non_present(None, ["some", "keys"])

        self.assertEqual(ret, {"some": None, "keys": None})

    def test_update_with_defined_value(self):
        ref = dict()
        val = object()
        ret = dict_update_non_present(ref, ["some", "keys"], val)

        self.assertIs(ret, ref)
        self.assertEqual(set(ret.keys()), set(["some", "keys"]))
        self.assertIs(ret["some"], val)
        self.assertIs(ret["keys"], val)

    def test_update_with_non_empy_dict(self):
        ref = {"some": None}
        ret = dict_update_non_present(ref, ["keys"])

        self.assertEqual(ret, {"some": None, "keys": None})

    def test_duplicated_keys(self):
        with self.assertRaises(ValueError) as e:
            dict_update_non_present(None, ["duplicated_key", "duplicated_key"])

        self.assertIn("duplicated_key", str(e.exception))

    def test_value_redefinition(self):
        ref = {"duplicated_key": object()}
        with self.assertRaises(ValueError) as e:
            dict_update_non_present(ref, ["duplicated_key"])

        self.assertIn("duplicated_key", str(e.exception))
