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
        ExpectCertificateRequest

from tlslite.constants import ContentType, HandshakeType, ExtensionType, \
        AlertLevel, AlertDescription, ClientCertificateType, HashAlgorithm, \
        SignatureAlgorithm
from tlslite.messages import Message, ServerHello, CertificateRequest
from tlslite.extensions import SNIExtension, TLSExtension
from tlsfuzzer.runner import ConnectionState
from tlsfuzzer.messages import RenegotiationInfoExtension

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
