# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function

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
import sys

from tlsfuzzer.expect import Expect, ExpectHandshake, ExpectServerHello, \
        ExpectCertificate, ExpectServerHelloDone, ExpectChangeCipherSpec, \
        ExpectFinished, ExpectAlert, ExpectApplicationData, \
        ExpectCertificateRequest, ExpectServerKeyExchange, \
        ExpectServerHello2, ExpectVerify, ExpectSSL2Alert, \
        ExpectCertificateStatus, ExpectNoMessage, srv_ext_handler_ems, \
        srv_ext_handler_etm, srv_ext_handler_sni, srv_ext_handler_renego, \
        srv_ext_handler_alpn, srv_ext_handler_ec_point, srv_ext_handler_npn, \
        srv_ext_handler_key_share, srv_ext_handler_supp_vers, \
        ExpectCertificateVerify, ExpectEncryptedExtensions, \
        ExpectNewSessionTicket, hrr_ext_handler_key_share, \
        hrr_ext_handler_cookie, ExpectHelloRetryRequest

from tlslite.constants import ContentType, HandshakeType, ExtensionType, \
        AlertLevel, AlertDescription, ClientCertificateType, HashAlgorithm, \
        SignatureAlgorithm, CipherSuite, CertificateType, SSL2HandshakeType, \
        SSL2ErrorDescription, GroupName, CertificateStatusType, ECPointFormat,\
        SignatureScheme, TLS_1_3_HRR
from tlslite.messages import Message, ServerHello, CertificateRequest, \
        ClientHello, Certificate, ServerHello2, ServerFinished, \
        ServerKeyExchange, CertificateStatus, CertificateVerify, \
        Finished, EncryptedExtensions, NewSessionTicket
from tlslite.extensions import SNIExtension, TLSExtension, \
        SupportedGroupsExtension, ALPNExtension, ECPointFormatsExtension, \
        NPNExtension, ServerKeyShareExtension, ClientKeyShareExtension, \
        SrvSupportedVersionsExtension, SupportedVersionsExtension, \
        HRRKeyShareExtension, CookieExtension
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509certchain import X509CertChain, X509
from tlslite.extensions import SNIExtension, SignatureAlgorithmsExtension
from tlslite.keyexchange import DHE_RSAKeyExchange, ECDHE_RSAKeyExchange
from tlslite.errors import TLSIllegalParameterException, TLSDecryptionFailed
from tlsfuzzer.runner import ConnectionState
from tlslite.extensions import RenegotiationInfoExtension
from tlsfuzzer.helpers import key_share_gen
from tlslite.keyexchange import ECDHKeyExchange

srv_raw_key = str(
    "-----BEGIN RSA PRIVATE KEY-----\n"\
    "MIICXQIBAAKBgQDRCQR5qRLJX8sy1N4BF1G1fml1vNW5S6o4h3PeWDtg7JEn+jIt\n"\
    "M/NZekrGv/+3gU9C9ixImJU6U+Tz3kU27qw0X+4lDJAZ8VZgqQTp/MWJ9Dqz2Syy\n"\
    "yQWUvUNUj90P9mfuyDO5rY/VLIskdBNOzUy0xvXvT99fYQE+QPP7aRgo3QIDAQAB\n"\
    "AoGAVSLbE8HsyN+fHwDbuo4I1Wa7BRz33xQWLBfe9TvyUzOGm0WnkgmKn3LTacdh\n"\
    "GxgrdBZXSun6PVtV8I0im5DxyVaNdi33sp+PIkZU386f1VUqcnYnmgsnsUQEBJQu\n"\
    "fUZmgNM+bfR+Rfli4Mew8lQ0sorZ+d2/5fsM0g80Qhi5M3ECQQDvXeCyrcy0u/HZ\n"\
    "FNjIloyXaAIvavZ6Lc6gfznCSfHc5YwplOY7dIWp8FRRJcyXkA370l5dJ0EXj5Gx\n"\
    "udV9QQ43AkEA34+RxjRk4DT7Zo+tbM/Fkoi7jh1/0hFkU5NDHweJeH/mJseiHtsH\n"\
    "KOcPGtEGBBqT2KNPWVz4Fj19LiUmmjWXiwJBAIBs49O5/+ywMdAAqVblv0S0nweF\n"\
    "4fwne4cM+5ZMSiH0XsEojGY13EkTEon/N8fRmE8VzV85YmkbtFWgmPR85P0CQQCs\n"\
    "elWbN10EZZv3+q1wH7RsYzVgZX3yEhz3JcxJKkVzRCnKjYaUi6MweWN76vvbOq4K\n"\
    "G6Tiawm0Duh/K4ZmvyYVAkBppE5RRQqXiv1KF9bArcAJHvLm0vnHPpf1yIQr5bW6\n"\
    "njBuL4qcxlaKJVGRXT7yFtj2fj0gv3914jY2suWqp8XJ\n"\
    "-----END RSA PRIVATE KEY-----\n"\
    )

srv_raw_certificate = str(
    "-----BEGIN CERTIFICATE-----\n"\
    "MIIB9jCCAV+gAwIBAgIJAMyn9DpsTG55MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNV\n"\
    "BAMMCWxvY2FsaG9zdDAeFw0xNTAxMjExNDQzMDFaFw0xNTAyMjAxNDQzMDFaMBQx\n"\
    "EjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA\n"\
    "0QkEeakSyV/LMtTeARdRtX5pdbzVuUuqOIdz3lg7YOyRJ/oyLTPzWXpKxr//t4FP\n"\
    "QvYsSJiVOlPk895FNu6sNF/uJQyQGfFWYKkE6fzFifQ6s9kssskFlL1DVI/dD/Zn\n"\
    "7sgzua2P1SyLJHQTTs1MtMb170/fX2EBPkDz+2kYKN0CAwEAAaNQME4wHQYDVR0O\n"\
    "BBYEFJtvXbRmxRFXYVMOPH/29pXCpGmLMB8GA1UdIwQYMBaAFJtvXbRmxRFXYVMO\n"\
    "PH/29pXCpGmLMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAkOgC7LP/\n"\
    "Rd6uJXY28HlD2K+/hMh1C3SRT855ggiCMiwstTHACGgNM+AZNqt6k8nSfXc6k1gw\n"\
    "5a7SGjzkWzMaZC3ChBeCzt/vIAGlMyXeqTRhjTCdc/ygRv3NPrhUKKsxUYyXRk5v\n"\
    "g/g6MwxzXfQP3IyFu3a9Jia/P89Z1rQCNRY=\n"\
    "-----END CERTIFICATE-----\n"\
    )

class TestExpect(unittest.TestCase):
    def test___init__(self):
        exp = Expect(ContentType.handshake)

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = Expect(ContentType.handshake)

        with self.assertRaises(NotImplementedError):
            exp.process(None, None)


class TestExpectNoMessage(unittest.TestCase):
    def test___init__(self):
        timeout = mock.Mock()
        exp = ExpectNoMessage(timeout)

        self.assertIsNotNone(exp)
        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())
        self.assertIs(exp.timeout, timeout)

    def test_process(self):
        exp = ExpectNoMessage()

        exp.process(None, None)


class TestExpectHandshake(unittest.TestCase):
    def test_process(self):
        exp = ExpectHandshake(ContentType.handshake,
                              HandshakeType.client_hello)

        with self.assertRaises(NotImplementedError):
            exp.process(None, None)

    def test_is_match_with_empty_message(self):
        exp = ExpectHandshake(ContentType.handshake,
                              HandshakeType.client_hello)

        ret = exp.is_match(Message(ContentType.handshake, bytearray(0)))

        self.assertFalse(ret)


class TestServerExtensionProcessors(unittest.TestCase):
    def test_srv_ext_handler_ems(self):
        ext = TLSExtension(extType=ExtensionType.extended_master_secret)

        state = ConnectionState()

        srv_ext_handler_ems(state, ext)

        self.assertTrue(state.extended_master_secret)

    def test_srv_ext_handler_ems_with_malformed_extension(self):
        ext = TLSExtension(extType=ExtensionType.extended_master_secret)
        ext.create(bytearray(1))

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_ems(state, ext)


    def test_srv_ext_handler_etm(self):
        ext = TLSExtension(extType=ExtensionType.encrypt_then_mac)

        state = ConnectionState()

        srv_ext_handler_etm(state, ext)

        self.assertTrue(state.encrypt_then_mac)

    def test_srv_ext_handler_etm_with_malformed_extension(self):
        ext = TLSExtension(extType=ExtensionType.encrypt_then_mac)
        ext.create(bytearray(1))

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_etm(state, ext)


    def test_srv_ext_handler_sni(self):
        ext = SNIExtension()

        state = ConnectionState()

        srv_ext_handler_sni(state, ext)

    def test_srv_ext_handler_sni_with_malformed_extension(self):
        ext = SNIExtension().create(b'example.com')

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_sni(state, ext)


    def test_srv_ext_handler_renego(self):
        ext = RenegotiationInfoExtension().create(bytearray(b'abba'))

        state = ConnectionState()
        state.key['client_verify_data'] = bytearray(b'ab')
        state.key['server_verify_data'] = bytearray(b'ba')

        srv_ext_handler_renego(state, ext)

    def test_srv_ext_handler_renego_with_malformed_extension(self):
        ext = RenegotiationInfoExtension()

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_renego(state, ext)

    def test_srv_ext_handler_alpn(self):
        ext = ALPNExtension().create([b'http/1.1'])

        state = ConnectionState()
        client_hello = ClientHello()
        cln_ext = ALPNExtension().create([b'http/1.1', b'spdy2', b'h2'])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        srv_ext_handler_alpn(state, ext)

    def test_srv_ext_handler_alpn_with_malformed_extension(self):
        ext = ALPNExtension()

        state = ConnectionState()
        client_hello = ClientHello()
        cln_ext = ALPNExtension().create([b'http/1.1', b'spdy2', b'h2'])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        with self.assertRaises(AssertionError):
            srv_ext_handler_alpn(state, ext)

    def test_srv_ext_handler_alpn_with_wrong_protocol(self):
        ext = ALPNExtension().create([b'http/1.0'])

        state = ConnectionState()
        client_hello = ClientHello()
        cln_ext = ALPNExtension().create([b'http/1.1', b'spdy2', b'h2'])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        with self.assertRaises(AssertionError):
            srv_ext_handler_alpn(state, ext)


    def test_srv_ext_handler_ec_point(self):
        ext = ECPointFormatsExtension().create([ECPointFormat.uncompressed])

        state = ConnectionState()

        srv_ext_handler_ec_point(state, ext)

    def test_srv_ext_handler_ec_point_with_malformed_extension(self):
        ext = ECPointFormatsExtension()

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_ec_point(state, ext)

    def test_srv_ext_handler_npn(self):
        ext = NPNExtension().create([b'http/1.1'])

        state = ConnectionState()

        srv_ext_handler_npn(state, ext)

    def test_srv_ext_handler_npn_with_malformed_extension(self):
        ext = NPNExtension()

        state = ConnectionState()

        with self.assertRaises(AssertionError):
            srv_ext_handler_npn(state, ext)

    def test_srv_ext_handler_key_share(self):
        s_ks = key_share_gen(GroupName.secp256r1)
        s_private = s_ks.private
        s_ks.private = None

        ext = ServerKeyShareExtension().create(s_ks)

        state = ConnectionState()

        client_hello = ClientHello()
        c_ks = key_share_gen(GroupName.secp256r1)
        cln_ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        srv_ext_handler_key_share(state, ext)

        kex = ECDHKeyExchange(GroupName.secp256r1, (3, 4))
        shared = kex.calc_shared_key(s_private, c_ks.key_exchange)

        self.assertEqual(state.key['DH shared secret'], shared)

    def test_srv_ext_handler_key_share_bad_srv_group(self):
        s_ks = key_share_gen(GroupName.secp256r1)
        ext = ServerKeyShareExtension().create(s_ks)

        state = ConnectionState()

        client_hello = ClientHello()
        c_ks = key_share_gen(GroupName.x25519)
        cln_ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        with self.assertRaises(AssertionError) as exc:
            srv_ext_handler_key_share(state, ext)

        self.assertIn("secp256r1", str(exc.exception))
        self.assertIn("didn't advertise", str(exc.exception))

    def test_srv_ext_handler_supp_vers(self):
        ext = SrvSupportedVersionsExtension().create((3, 4))

        state = ConnectionState()

        client_hello = ClientHello()
        cln_ext = SupportedVersionsExtension().create([(3, 4)])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        srv_ext_handler_supp_vers(state, ext)

        self.assertEqual(state.version, ext.version)

    def test_srv_ext_handler_supp_vers_with_wrong_version(self):
        ext = SrvSupportedVersionsExtension().create((3, 9))

        state = ConnectionState()

        client_hello = ClientHello()
        cln_ext = SupportedVersionsExtension().create([(3, 4), (3, 5)])
        client_hello.extensions = [cln_ext]
        state.handshake_messages.append(client_hello)

        with self.assertRaises(AssertionError) as exc:
            srv_ext_handler_supp_vers(state, ext)

        self.assertIn("(3, 9)", str(exc.exception))
        self.assertIn("didn't advertise", str(exc.exception))


class TestHRRExtensionProcessors(unittest.TestCase):
    def test_hrr_ext_handler_key_share(self):
        ext = HRRKeyShareExtension().create(GroupName.secp256r1)
        state = ConnectionState()

        ch_ext = SupportedGroupsExtension().create([GroupName.secp256r1,
                                                    GroupName.secp384r1])
        ch = ClientHello()
        ch.extensions = [ch_ext]

        state.handshake_messages.append(ch)

        hrr_ext_handler_key_share(state, ext)

    def test_hrr_ext_handler_with_wrong_group(self):
        ext = HRRKeyShareExtension().create(GroupName.x25519)
        state = ConnectionState()

        ch_ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        ch = ClientHello()
        ch.extensions = [ch_ext]

        state.handshake_messages.append(ch)

        with self.assertRaises(AssertionError) as e:
            hrr_ext_handler_key_share(state, ext)

        self.assertIn("didn't advertise", str(e.exception))

    def test_hrr_ext_handler_cookie(self):
        ext = CookieExtension().create(b'some payload')
        state = None

        hrr_ext_handler_cookie(state, ext)

    def test_hrr_ext_handler_cookie_with_empty_payload(self):
        ext = CookieExtension()
        state = None

        with self.assertRaises(AssertionError) as e:
            hrr_ext_handler_cookie(state, ext)

        self.assertIn("empty cookie", str(e.exception))


class TestExpectServerHello(unittest.TestCase):
    def test___init__(self):
        exp = ExpectServerHello()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectServerHello()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.server_hello]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectServerHello()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.server_hello]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectServerHello()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.client_hello]))

        self.assertFalse(exp.is_match(msg))

    def test_process_with_extensions(self):
        extension_process = mock.MagicMock()
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            extension_process})

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

        extension_process.assert_called_once_with(state, ext)

    def test_process_with_automatic_extension_handling(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None})

        state = ConnectionState()
        client_hello = ClientHello()
        renego = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, renego]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

    def test_process_with_missing_extensions(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None})

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=None)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_missing_specified_extension(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None,
                                            ExtensionType.alpn: None})

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        ext = ALPNExtension().create([b'h2'])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(bytearray())
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_extra_extensions(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                            None})

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        ext = ALPNExtension().create([b'h2'])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = [RenegotiationInfoExtension().create(bytearray()),
                ALPNExtension().create([b'h2'])]

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_no_autohandler(self):
        exp = ExpectServerHello(extensions={1: None})

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        ext = TLSExtension(extType=1).create(bytearray())
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = TLSExtension(extType=1).create(bytearray())

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_non_matching_example(self):
        exp = ExpectServerHello(extensions={1: TLSExtension(extType=1)})

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        ext = TLSExtension(extType=1).create(bytearray())
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = TLSExtension(extType=1).create(bytearray(1))

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_incorrect_version(self):
        extension_process = mock.MagicMock()
        exp = ExpectServerHello(version=(3, 3))

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 2),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_incorrect_cipher(self):
        exp = ExpectServerHello(cipher=5)

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_unexpected_cipher(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=5)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_udefined_cipher(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create(None)

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=0xfff0)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_no_matching_extension(self):
        exps = {ExtensionType.renegotiation_info: None,
                ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])
               }
        exp = ExpectServerHello(extensions=exps)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = []
        exts.append(RenegotiationInfoExtension().create(None))
        exts.append(ALPNExtension().create([bytearray(b'http/1.2')]))
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_matching_extension(self):
        exps = {ExtensionType.renegotiation_info: None,
                ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])
               }
        exp = ExpectServerHello(extensions=exps)

        state = ConnectionState()
        client_hello = ClientHello()
        ciph = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, ciph]
        ext = ALPNExtension().create([bytearray(b'http/1.1')])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = []
        exts.append(RenegotiationInfoExtension().create(bytearray()))
        exts.append(ALPNExtension().create([bytearray(b'http/1.1')]))
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)
        self.assertIsInstance(state.handshake_messages[1], ServerHello)

    def test_process_with_bad_extension_handler(self):
        exps = {ExtensionType.renegotiation_info: None,
                ExtensionType.alpn: 'BAD_EXTENSION'
               }
        exp = ExpectServerHello(extensions=exps)

        state = ConnectionState()
        client_hello = ClientHello()
        renego = CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        client_hello.cipher_suites = [4, renego]
        ext = ALPNExtension().create([bytearray(b'http/1.1')])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = []
        exts.append(RenegotiationInfoExtension().create(bytearray()))
        exts.append(ALPNExtension().create([bytearray(b'http/1.1')]))
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(ValueError):
            exp.process(state, msg)

    def test_process_with_unexpected_extensions(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                           None})

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        exts = []
        exts.append(RenegotiationInfoExtension().create(None))
        exts.append(SNIExtension().create())
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=exts)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_resumption(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()
        state.session_id = bytearray(b'\xaa\xaa\xaa')
        state.cipher = 4

        self.assertFalse(state.resuming)

        msg = ServerHello()
        msg.create(version=(3, 3),
                   random=bytearray(32),
                   session_id=bytearray(b'\xaa\xaa\xaa'),
                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

        self.assertTrue(state.resuming)

    def test_process_with_mandatory_resumption(self):
        exp = ExpectServerHello(resume=True)

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()
        state.session_id = bytearray(b'\xaa\xaa\xaa')
        state.cipher = 4

        self.assertFalse(state.resuming)

        msg = ServerHello()
        msg.create(version=(3, 3),
                   random=bytearray(32),
                   session_id=bytearray(b'\xaa\xaa\xaa'),
                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

        self.assertTrue(state.resuming)


    def test_process_with_mandatory_resumption_but_wrong_id(self):
        exp = ExpectServerHello(resume=True)

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.session_id = bytearray(b'\xaa\xaa\xaa')
        state.cipher = 4

        self.assertFalse(state.resuming)

        msg = ServerHello()
        msg.create(version=(3, 3),
                   random=bytearray(32),
                   session_id=bytearray(b'\xbb\xbb\xbb'),
                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_extended_master_secret(self):
        exp = ExpectServerHello(
                extensions={ExtensionType.extended_master_secret:None})

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.cipher_suites = [4]
        ext = TLSExtension(extType=ExtensionType.extended_master_secret)
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()
        self.assertFalse(state.extended_master_secret)

        ext = TLSExtension(extType=ExtensionType.extended_master_secret)
        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

        self.assertTrue(state.extended_master_secret)

    def test_process_with_tls13_settings(self):
        exp = ExpectServerHello()

        state = ConnectionState()
        client_hello = ClientHello()
        client_hello.extensions = []
        client_hello.cipher_suites = [CipherSuite.TLS_AES_128_GCM_SHA256]
        ext = SupportedGroupsExtension().create([GroupName.secp256r1])
        client_hello.extensions.append(ext)
        c_ks = key_share_gen(GroupName.secp256r1)
        ext = ClientKeyShareExtension().create([c_ks])
        client_hello.extensions.append(ext)
        ext = SupportedVersionsExtension().create([(3, 3), (3, 4)])
        client_hello.extensions.append(ext)
        state.handshake_messages.append(client_hello)
        state.msg_sock = mock.MagicMock()

        s_ext = []
        s_ks = key_share_gen(GroupName.secp256r1)
        ext = ServerKeyShareExtension().create(s_ks)
        s_ext.append(ext)
        ext = SrvSupportedVersionsExtension().create((3, 4))
        s_ext.append(ext)
        server_hello = ServerHello().create(version=(3, 3),
                                            random=bytearray(32),
                                            session_id=bytearray(0),
                                            cipher_suite=
                                            CipherSuite.TLS_AES_128_GCM_SHA256,
                                            extensions=s_ext)

        exp.process(state, server_hello)

        state.msg_sock.calcTLS1_3PendingState.assert_called_once_with(
            state.cipher,
            state.key['client handshake traffic secret'],
            state.key['server handshake traffic secret'],
            None)
        state.msg_sock.changeReadState.assert_called_once_with()
        self.assertTrue(state.key['handshake secret'])
        self.assertTrue(state.key['client handshake traffic secret'])
        self.assertTrue(state.key['server handshake traffic secret'])
        self.assertEqual(state.version, (3, 4))
        self.assertTrue(state.msg_sock.tls13record)


class TestExpectServerHelloWithHelloRetryRequest(unittest.TestCase):
    def setUp(self):
        self.exp = ExpectServerHello()

        state = ConnectionState()
        self.state = state
        state.msg_sock = mock.MagicMock()
        state.key['DH shared secret'] = bytearray()

        exts = [SupportedVersionsExtension().create([(3, 5), (3, 4), (3, 3)])]
        ch = ClientHello()
        ch.create((3, 3), bytearray(32), b'', [4, 5], extensions=exts)
        self.ch = ch
        state.handshake_messages.append(ch)

        exts = [SrvSupportedVersionsExtension().create((3, 4))]
        hrr = ServerHello()
        hrr.create((3, 3), TLS_1_3_HRR, b'', 0x0004, extensions=exts)
        self.hrr = hrr
        state.handshake_messages.append(hrr)

        exts = [SrvSupportedVersionsExtension().create((3, 4))]
        sh = ServerHello()
        sh.create((3, 3), bytearray(32), b'', 0x0004, extensions=exts)
        self.sh = sh

    def test_with_hello_retry_request(self):
        self.exp.process(self.state, self.sh)

    def test_with_wrong_hrr_random(self):
        self.hrr.random = bytearray([12]*32)

        with self.assertRaises(ValueError) as e:
            self.exp.process(self.state, self.sh)

        self.assertIn("Two ServerHello", str(e.exception))

    def test_with_wrong_cipher_suite(self):
        self.sh.cipher_suite = 5

        with self.assertRaises(AssertionError) as e:
            self.exp.process(self.state, self.sh)

        self.assertIn("different cipher suite", str(e.exception))

    def test_with_wrong_version(self):
        self.sh.extensions[0].version = (3, 5)

        with self.assertRaises(AssertionError) as e:
            self.exp.process(self.state, self.sh)

        self.assertIn("different protocol version", str(e.exception))


class TestExpectHelloRetryRequest(unittest.TestCase):
    def test___init__(self):
        exp = ExpectHelloRetryRequest()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectHelloRetryRequest()

        # the difference between HRR and Server Hello is the random value,
        # not the content type or handshake type
        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.server_hello]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatched_handshake_type(self):
        exp = ExpectHelloRetryRequest()

        msg = Message(ContentType.handshake,
                      # this is legacy value, used in early drafts of TLS 1.3
                      bytearray([HandshakeType.hello_retry_request]))

        self.assertFalse(exp.is_match(msg))

    def test_process_with_extensions(self):
        state = ConnectionState()

        ch = ClientHello()
        ch.cipher_suites = [4]
        ch.extensions = [SupportedVersionsExtension().create([(3, 4)])]

        state.handshake_messages.append(ch)
        state.msg_sock = mock.MagicMock()

        exts = [CookieExtension().create(b'some payload'),
                SrvSupportedVersionsExtension().create((3, 4))]
        hrr = ServerHello()
        hrr.create((3, 3), TLS_1_3_HRR, b'', 0x0004, extensions=exts)

        exp = ExpectHelloRetryRequest()

        exp.process(state, hrr)

        self.maxDiff = None
        self.assertEqual(
            b'\x99\xb9\xa5O\x9d\x819\xfe\xd6\xf5\x8d\xce'
            b' bW\x1fO0[7\x04\x15\x89\xaeS\xcd8*3C\x9d\x01',
            state.handshake_hashes.digest('sha256'))

    def test_process_with_unexpected_extensions(self):
        state = ConnectionState()

        ch = ClientHello()
        ch.cipher_suites = [4]
        ch.extensions = [TLSExtension(extType=0x13ff)]
        state.handshake_messages.append(ch)
        state.msg_sock = mock.MagicMock()

        exts = [TLSExtension(extType=0x13ff)]
        hrr = ServerHello()
        hrr.create((3, 3), TLS_1_3_HRR, b'', 0x0004, extensions=exts)

        exp = ExpectHelloRetryRequest()

        with self.assertRaises(AssertionError) as e:
            exp.process(state, hrr)

        self.assertIn("No autohandler for 5119", str(e.exception))


class TestExpectServerHello2(unittest.TestCase):
    def test___init__(self):
        exp = ExpectServerHello2()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectServerHello2()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        msg = ServerHello2()
        msg.session_id_hit = 1
        msg.session_id = bytearray(b'\x12')
        msg.certificate = X509().parse(srv_raw_certificate).writeBytes()

        ret = exp.process(state, msg)

        self.assertEqual(state.session_id, msg.session_id)

    def test_process_with_version(self):
        exp = ExpectServerHello2((2, 0))

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        msg = ServerHello2()
        msg.session_id_hit = 1
        msg.session_id = bytearray(b'\x12')
        msg.server_version = (2, 0)
        msg.certificate = X509().parse(srv_raw_certificate).writeBytes()

        ret = exp.process(state, msg)

        self.assertEqual(state.session_id, msg.session_id)

class TestExpectCertificate(unittest.TestCase):
    def test___init__(self):
        exp = ExpectCertificate()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectCertificate()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectCertificate()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.certificate]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectCertificate()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.client_hello]))

        self.assertFalse(exp.is_match(msg))

    def test_process(self):
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        exp = ExpectCertificate()

        msg = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        exp.process(state, msg)


class TestExpectCertificateVerify(unittest.TestCase):
    def test___init__(self):
        exp = ExpectCertificate()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectCertificateVerify()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate_verify]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectCertificateVerify()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.certificate_verify]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectCertificateVerify()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate]))

        self.assertFalse(exp.is_match(msg))

    def test_process(self):
        exp = ExpectCertificateVerify()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.rsa_pss_rsae_sha384])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      "PSS",
                                      "sha384",
                                      48)
        scheme = SignatureScheme.rsa_pss_rsae_sha384
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    def test_process_with_expected_sig_alg(self):
        exp = ExpectCertificateVerify(
            sig_alg=SignatureScheme.rsa_pss_rsae_sha384)

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.rsa_pss_rsae_sha384])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      "PSS",
                                      "sha384",
                                      48)
        scheme = SignatureScheme.rsa_pss_rsae_sha384
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        exp.process(state, cer_verify)

    def test_process_with_invalid_signature(self):
        exp = ExpectCertificateVerify(
            sig_alg=SignatureScheme.rsa_pss_rsae_sha384)

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)

        cert = Certificate(CertificateType.x509, (3, 4)).create(
            X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)

        client_hello = ClientHello()
        ext = SignatureAlgorithmsExtension().\
            create([SignatureScheme.rsa_pss_rsae_sha384])
        client_hello.extensions = [ext]
        state.handshake_messages.append(client_hello)

        state.handshake_messages.append(cert)

        hh_digest = state.handshake_hashes.digest('sha256')
        self.assertEqual(state.prf_name, "sha256")
        signature_context = bytearray(b'\x20' * 64 +
                                      b'TLS 1.3, server CertificateVerify' +
                                      b'\x00') + hh_digest
        sig = private_key.hashAndSign(signature_context,
                                      "PSS",
                                      "sha384",
                                      48)
        sig[-1] ^= 1
        scheme = SignatureScheme.rsa_pss_rsae_sha384
        cer_verify = CertificateVerify((3, 4)).create(sig, scheme)

        with self.assertRaises(AssertionError) as exc:
            exp.process(state, cer_verify)

        self.assertIn("verification failed", str(exc.exception))


class TestExpectCertificateStatus(unittest.TestCase):
    def test___init__(self):
        exp = ExpectCertificateStatus()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectCertificateStatus()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate_status]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectCertificateStatus()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.certificate_status]))

        self.assertFalse(exp.is_match(msg))

    def test_process(self):
        exp = ExpectCertificateStatus()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        msg = CertificateStatus().create(CertificateStatusType.ocsp,
                                         bytearray(10))

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)


class TestExpectServerHelloDone(unittest.TestCase):
    def test___init__(self):
        exp = ExpectServerHelloDone()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectServerHelloDone()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.server_hello_done]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectServerHelloDone()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.server_hello_done]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectServerHelloDone()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.client_hello]))

        self.assertFalse(exp.is_match(msg))

class TestExpectChangeCipherSpec(unittest.TestCase):
    def test___init__(self):
        exp = ExpectChangeCipherSpec()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectChangeCipherSpec()

        msg = Message(ContentType.change_cipher_spec,
                      bytearray([0]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectChangeCipherSpec()

        msg = Message(ContentType.application_data,
                      bytearray([0]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_arbitrary_data(self):
        exp = ExpectChangeCipherSpec()

        msg = Message(ContentType.change_cipher_spec,
                      bytearray([243]))

        self.assertTrue(exp.is_match(msg))

    def test_process(self):
        exp = ExpectChangeCipherSpec()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        msg = Message(ContentType.change_cipher_spec, bytearray([1]))

        exp.process(state, msg)

        state.msg_sock.calcPendingStates.assert_not_called()
        state.msg_sock.changeReadState.assert_called_once_with()

    def test_process_with_resumption(self):
        exp = ExpectChangeCipherSpec()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.resuming = True

        state.cipher = mock.Mock(name="cipher")
        state.key['master_secret'] = mock.Mock(name="master_secret")
        state.client_random = mock.Mock(name="client_random")
        state.server_random = mock.Mock(name="server_random")

        msg = Message(ContentType.change_cipher_spec, bytearray([1]))

        exp.process(state, msg)

        state.msg_sock.calcPendingStates.assert_called_once_with(
                state.cipher,
                state.key['master_secret'],
                state.client_random,
                state.server_random,
                None)
        state.msg_sock.changeReadState.assert_called_once_with()

class TestExpectFinished(unittest.TestCase):
    def test___init__(self):
        exp = ExpectFinished()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test___init___with_ssl2(self):
        exp = ExpectFinished(version=(2, 0))

        self.assertIsNotNone(exp)
        self.assertTrue(exp.is_expect())
        self.assertEqual(exp.version, (2, 0))

    def test_is_match(self):
        exp = ExpectFinished()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.finished]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_content_type(self):
        exp = ExpectFinished()

        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.finished]))

        self.assertFalse(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectFinished()

        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.client_hello]))

        self.assertFalse(exp.is_match(msg))

    def test_process(self):
        exp = ExpectFinished()
        # this probably should use mock objects to check if calcFinished
        # is called with them
        state = ConnectionState()
        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.finished, 0, 0, 12]) + 
                      bytearray(b"\xa3;\x9c\xc9\'E\xbc\xf6\xc7\x96\xaf\x7f"))

        exp.process(state, msg)

    def test_process_with_tls13(self):
        exp = ExpectFinished()
        state = ConnectionState()
        state.cipher = CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)
        state.key['server handshake traffic secret'] = bytearray(32)
        state.msg_sock = mock.MagicMock()
        msg = Finished((3, 4), 32).create(
            bytearray(b'\x14\xa5e\xa67\xfe\xa3(\xd3\xac\x95\xecX\xb7\xc0\xd4'
                      b'u\xef\xb3V\x8f\xc7[\xcdD\xc8\xa4\x86\xcf\xd3\xc9\x0c'))

        exp.process(state, msg)

        state.msg_sock.changeWriteState.assert_called_once_with()

    def test_process_with_ssl2(self):
        exp = ExpectFinished((2, 0))
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        msg = ServerFinished().create(bytearray(range(12)))

        exp.process(state, msg)


class TestExpectEncryptedExtensions(unittest.TestCase):
    def test___init__(self):
        exp = ExpectEncryptedExtensions()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectEncryptedExtensions()

        ee = EncryptedExtensions().create([])

        state = ConnectionState()

        exp.process(state, ee)

        self.assertIn(ee, state.handshake_messages)


class TestExpectNewSessionTicket(unittest.TestCase):
    def test___init__(self):
        exp = ExpectNewSessionTicket()

        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectNewSessionTicket()

        nst = NewSessionTicket().create(12, 44, b'abba', b'I am a ticket', [])

        state = ConnectionState()

        exp.process(state, nst)

        self.assertIn(nst, state.session_tickets)


class TestExpectVerify(unittest.TestCase):
    def test___init__(self):
        exp = ExpectVerify()
        self.assertIsNotNone(exp)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectVerify()
        msg = Message(ContentType.handshake,
                      bytearray([SSL2HandshakeType.server_verify]))

        exp.process(None, msg)

class TestExpectAlert(unittest.TestCase):
    def test___init__(self):
        exp = ExpectAlert()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test___init___with_values(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.unknown_psk_identity)

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectAlert()

        msg = Message(ContentType.alert,
                      bytearray(2))

        self.assertTrue(exp.is_match(msg))

    def test_process(self):
        exp = ExpectAlert()

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(2))

        exp.process(state, msg)

    def test_is_match_with_values(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.unknown_psk_identity)

        msg = Message(ContentType.alert,
                      bytearray(2))

        self.assertTrue(exp.is_match(msg))

    def test_process_with_values(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.unknown_psk_identity)

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\x01\x73'))

        exp.process(state, msg)

    def test_process_with_values_and_not_matching_level(self):
        exp = ExpectAlert(AlertLevel.fatal,
                          AlertDescription.unknown_psk_identity)

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\x01\x73'))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_multiple_values_one_matching_description(self):
        exp = ExpectAlert(AlertLevel.fatal,
                          [AlertDescription.record_overflow,
                           AlertDescription.decompression_failure])

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\x02\x16'))

        # does NOT raise exception
        exp.process(state, msg)

    def test_process_with_values_and_not_matching_description(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.bad_record_mac)

        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\x01\x73'))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_values_not_matching_anything(self):
        exp = ExpectAlert(AlertLevel.warning,
                          AlertDescription.bad_record_mac)
        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\xff\xff'))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertEqual(str(e.exception),
                         "Alert level 255 != 1, "
                         "Expected alert description "
                         "\"bad_record_mac\" does not match received "
                         "\"255\"")

    def test_process_with_multiple_values_not_matching_anything(self):
        exp = ExpectAlert(AlertLevel.warning,
                          [AlertDescription.bad_record_mac,
                           AlertDescription.illegal_parameter])
        state = ConnectionState()
        msg = Message(ContentType.alert,
                      bytearray(b'\xff\xff'))

        with self.assertRaises(AssertionError) as e:
            exp.process(state, msg)

        self.assertEqual(str(e.exception),
                         "Alert level 255 != 1, "
                         "Expected alert description "
                         "\"bad_record_mac\" or \"illegal_parameter\" does "
                         "not match received "
                         "\"255\"")


class TestExpectSSL2Alert(unittest.TestCase):
    def test___init__(self):
        exp = ExpectSSL2Alert()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_process(self):
        exp = ExpectSSL2Alert(SSL2ErrorDescription.bad_certificate)

        msg = Message(ContentType.handshake,
                      bytearray([SSL2HandshakeType.error,
                                 0x00,
                                 0x04]))
        exp.process(None, msg)

    def test_process_with_non_matching_alert(self):
        exp = ExpectSSL2Alert(SSL2ErrorDescription.bad_certificate)
        msg = Message(ContentType.handshake,
                      bytearray([SSL2HandshakeType.error,
                                 0x00,
                                 0x01]))

        with self.assertRaises(AssertionError):
            exp.process(None, msg)

class TestExpectApplicationData(unittest.TestCase):
    def test___init__(self):
        exp = ExpectApplicationData()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectApplicationData()

        msg = Message(ContentType.application_data,
                      bytearray(0))

        self.assertTrue(exp.is_match(msg))

    def test_process(self):
        exp = ExpectApplicationData()

        state = ConnectionState()
        msg = Message(ContentType.application_data,
                      bytearray(0))

        exp.process(state, msg)

    def test_process_with_non_matching_data(self):
        exp = ExpectApplicationData(bytearray(b"hello"))

        state = ConnectionState()
        msg = Message(ContentType.application_data,
                      bytearray(b"bye"))

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

class TestExpectServerKeyExchange(unittest.TestCase):
    def test__init__(self):
        exp = ExpectServerKeyExchange()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.server_key_exchange]))

        self.assertTrue(exp.is_match(msg))

    def test_process(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SignatureAlgorithmsExtension().create(
            [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key)

        msg = srv_key_exchange.makeServerKeyExchange('sha256')

        exp.process(state, msg)

    def test_process_with_ECDHE_RSA(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SignatureAlgorithmsExtension().create(
            [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)]),
            SupportedGroupsExtension().create([GroupName.secp256r1])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = ECDHE_RSAKeyExchange(
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                [GroupName.secp256r1])

        msg = srv_key_exchange.makeServerKeyExchange('sha256')

        exp.process(state, msg)

    def test_process_with_ECDHE_RSA_bad_signature(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SignatureAlgorithmsExtension().create(
            [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)]),
            SupportedGroupsExtension().create([GroupName.secp256r1])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = ECDHE_RSAKeyExchange(
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                [GroupName.secp256r1])

        msg = srv_key_exchange.makeServerKeyExchange('sha256')
        msg.signature[-1] ^= 1

        print("Error printed below is expected", file=sys.stderr)
        with self.assertRaises(TLSDecryptionFailed):
            exp.process(state, msg)

    def test_process_with_default_signature_algorithm(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key)

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        exp.process(state, msg)

    def test_process_with_not_matching_signature_algorithms(self):
        exp = ExpectServerKeyExchange(valid_sig_algs=[(HashAlgorithm.sha256,
                                                       SignatureAlgorithm.rsa)])

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key)

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        with self.assertRaises(TLSIllegalParameterException):
            exp.process(state, msg)

    def test_process_with_unknown_key_exchange(self):
        exp = ExpectServerKeyExchange()

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))
        private_key = parsePEMKey(srv_raw_key, private=True)

        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SignatureAlgorithmsExtension().create(
            [(HashAlgorithm.sha256, SignatureAlgorithm.rsa)])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        state.version = server_hello.server_version
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        state.handshake_messages.append(cert)

        msg = ServerKeyExchange(state.cipher, state.version)
        msg.createSRP(1, 2, bytearray(3), 5)
        msg.signAlg = SignatureAlgorithm.rsa
        msg.hashAlg = HashAlgorithm.sha256
        hash_bytes = msg.hash(client_hello.random, server_hello.random)
        hash_bytes = private_key.addPKCS1Prefix(hash_bytes, 'sha256')
        msg.signature = private_key.sign(hash_bytes)

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_rcf7919_groups(self):
        exp = ExpectServerKeyExchange(valid_groups=[256])

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SupportedGroupsExtension().create([256])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                dhGroups=range(256, 258))

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        exp.process(state, msg)

    def test_process_with_rcf7919_groups_required_not_provided(self):
        exp = ExpectServerKeyExchange(valid_groups=[256])

        state = ConnectionState()
        state.cipher = CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA

        cert = Certificate(CertificateType.x509).\
                create(X509CertChain([X509().parse(srv_raw_certificate)]))

        private_key = parsePEMKey(srv_raw_key, private=True)
        client_hello = ClientHello()
        client_hello.client_version = (3, 3)
        client_hello.random = bytearray(32)
        client_hello.extensions = [SupportedGroupsExtension().create([256])]
        state.client_random = client_hello.random
        state.handshake_messages.append(client_hello)
        server_hello = ServerHello()
        server_hello.server_version = (3, 3)
        server_hello.random = bytearray(32)
        state.server_random = server_hello.random
        # server hello is not necessary for the test to work
        #state.handshake_messages.append(server_hello)
        state.handshake_messages.append(cert)
        srv_key_exchange = DHE_RSAKeyExchange(\
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                client_hello,
                server_hello,
                private_key,
                dhGroups=None)

        msg = srv_key_exchange.makeServerKeyExchange('sha1')

        with self.assertRaises(AssertionError):
            exp.process(state, msg)


class TestExpectCertificateRequest(unittest.TestCase):
    def test___init__(self):
        exp = ExpectCertificateRequest()

        self.assertTrue(exp.is_expect())
        self.assertFalse(exp.is_command())
        self.assertFalse(exp.is_generator())

    def test_is_match(self):
        exp = ExpectCertificateRequest()

        state = ConnectionState()
        msg = Message(ContentType.handshake,
                      bytearray([HandshakeType.certificate_request]))

        self.assertTrue(exp.is_match(msg))

    def test_is_match_with_unmatching_handshake_type(self):
        exp = ExpectCertificateRequest()

        state = ConnectionState()
        msg = Message(ContentType.application_data,
                      bytearray([HandshakeType.certificate_request]))

        self.assertFalse(exp.is_match(msg))

    def test_process(self):
        exp = ExpectCertificateRequest()

        state = ConnectionState()
        msg = CertificateRequest((3, 3))
        msg.create([ClientCertificateType.rsa_sign,
                    ClientCertificateType.rsa_fixed_dh],
                   [],
                   [(HashAlgorithm.sha1, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha384, SignatureAlgorithm.rsa)])
        msg = Message(ContentType.handshake,
                      msg.write())

        exp.process(state, msg)

    def test_sig_algs(self):
        sig_algs = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha384, SignatureAlgorithm.rsa)]
        exp = ExpectCertificateRequest(sig_algs=sig_algs)

        state = ConnectionState()
        msg = CertificateRequest((3, 3))
        msg.create([ClientCertificateType.rsa_sign,
                    ClientCertificateType.rsa_fixed_dh],
                   [],
                   sig_algs)
        msg = Message(ContentType.handshake, msg.write())

        exp.process(state, msg)

    def test_sig_algs_mismatched(self):
        sig_algs = [(HashAlgorithm.sha1, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                    (HashAlgorithm.sha384, SignatureAlgorithm.rsa)]
        exp = ExpectCertificateRequest(sig_algs=sig_algs[0:0])

        state = ConnectionState()
        msg = CertificateRequest((3, 3))
        msg.create([ClientCertificateType.rsa_sign,
                    ClientCertificateType.rsa_fixed_dh],
                   [],
                   sig_algs)
        msg = Message(ContentType.handshake, msg.write())

        with self.assertRaises(AssertionError):
            exp.process(state, msg)
