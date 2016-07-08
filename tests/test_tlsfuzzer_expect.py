# Author: Hubert Kario, (c) 2015
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

from tlsfuzzer.expect import Expect, ExpectHandshake, ExpectServerHello, \
        ExpectCertificate, ExpectServerHelloDone, ExpectChangeCipherSpec, \
        ExpectFinished, ExpectAlert, ExpectApplicationData, \
        ExpectCertificateRequest, ExpectServerKeyExchange, \
        ExpectServerHello2, ExpectVerify, ExpectSSL2Alert

from tlslite.constants import ContentType, HandshakeType, ExtensionType, \
        AlertLevel, AlertDescription, ClientCertificateType, HashAlgorithm, \
        SignatureAlgorithm, CipherSuite, CertificateType, SSL2HandshakeType, \
        SSL2ErrorDescription, GroupName
from tlslite.messages import Message, ServerHello, CertificateRequest, \
        ClientHello, Certificate, ServerHello2, ServerFinished, \
        ServerKeyExchange
from tlslite.extensions import SNIExtension, TLSExtension, \
        SupportedGroupsExtension
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509certchain import X509CertChain, X509
from tlslite.extensions import SNIExtension, SignatureAlgorithmsExtension
from tlslite.keyexchange import DHE_RSAKeyExchange, ECDHE_RSAKeyExchange
from tlslite.errors import TLSIllegalParameterException
from tlsfuzzer.runner import ConnectionState
from tlsfuzzer.messages import RenegotiationInfoExtension

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
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create()

        msg = ServerHello().create(version=(3, 3),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4,
                                   extensions=[ext])

        self.assertTrue(exp.is_match(msg))

        exp.process(state, msg)

        extension_process.assert_called_once_with(state, ext)

    def test_process_with_incorrect_version(self):
        extension_process = mock.MagicMock()
        exp = ExpectServerHello(version=(3, 3))

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        ext = RenegotiationInfoExtension().create()

        msg = ServerHello().create(version=(3, 2),
                                   random=bytearray(32),
                                   session_id=bytearray(0),
                                   cipher_suite=4)

        self.assertTrue(exp.is_match(msg))

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

    def test_process_with_unexpected_extensions(self):
        exp = ExpectServerHello(extensions={ExtensionType.renegotiation_info:
                                           None})

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        exts = []
        exts.append(RenegotiationInfoExtension().create())
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

        msg = Message(ContentType.change_cipher_spec, bytearray(1))

        exp.process(state, msg)

        state.msg_sock.calcPendingStates.assert_not_called()
        state.msg_sock.changeReadState.assert_called_once_with()

    def test_process_with_resumption(self):
        exp = ExpectChangeCipherSpec()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.resuming = True

        state.cipher = mock.Mock(name="cipher")
        state.master_secret = mock.Mock(name="master_secret")
        state.client_random = mock.Mock(name="client_random")
        state.server_random = mock.Mock(name="server_random")

        msg = Message(ContentType.change_cipher_spec, bytearray(1))

        exp.process(state, msg)

        state.msg_sock.calcPendingStates.assert_called_once_with(
                state.cipher,
                state.master_secret,
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

    def test_process_with_ssl2(self):
        exp = ExpectFinished((2, 0))
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        msg = ServerFinished().create(bytearray(range(12)))

        exp.process(state, msg)

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

        with self.assertRaises(AssertionError):
            exp.process(state, msg)

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
