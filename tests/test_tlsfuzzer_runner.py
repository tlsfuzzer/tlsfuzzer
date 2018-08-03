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

from tlsfuzzer.runner import ConnectionState, Runner, guess_response
from tlsfuzzer.expect import ExpectClose, ExpectNoMessage
from tlsfuzzer.messages import ClientHelloGenerator
import tlslite.messages as messages
import tlslite.constants as constants
from tlslite.x509certchain import X509CertChain
from tlslite.errors import TLSAbruptCloseError
import socket

class TestConnectionState(unittest.TestCase):
    def test___init__(self):
        state = ConnectionState()

        self.assertIsNotNone(state)

    def test_get_server_public_key(self):
        state = ConnectionState()

        with self.assertRaises(StopIteration):
            state.get_server_public_key()

    def test_get_server_public_key_with_valid_messages(self):
        state = ConnectionState()

        msg = messages.Certificate(constants.CertificateType.x509)
        cert_list = mock.MagicMock(spec=X509CertChain)
        cert_list.x509List = []
        msg.create(cert_list)

        state.handshake_messages.append(msg)

        state.get_server_public_key()
        self.assertTrue(cert_list.getEndEntityPublicKey.called)

    def test_get_last_message_of_type(self):
        state = ConnectionState()
        msg = messages.ServerHello()
        msg.server_version = (3, 1)
        state.handshake_messages.append(msg)

        msg = messages.ServerHello()
        msg.server_version = (3, 3)
        state.handshake_messages.append(msg)

        msg = state.get_last_message_of_type(messages.ServerHello)
        self.assertEqual(msg.server_version, (3, 3))

    def test_get_last_message_of_type_with_no_messages_of_that_type(self):
        state = ConnectionState()
        msg = messages.ServerHello()
        msg.server_version = (3, 1)
        state.handshake_messages.append(msg)

        msg = state.get_last_message_of_type(messages.ClientHello)
        self.assertIsNone(msg)

    def test_get_last_message_of_type_with_no_messages(self):
        state = ConnectionState()

        msg = state.get_last_message_of_type(messages.ClientHello)
        self.assertIsNone(msg)

    def test_prf_name_with_sha256(self):
        state = ConnectionState()
        state.cipher = constants.CipherSuite.TLS_AES_128_GCM_SHA256

        self.assertEqual(state.prf_name, "sha256")

    def test_prf_name_with_sha384(self):
        state = ConnectionState()
        state.cipher = constants.CipherSuite.TLS_AES_256_GCM_SHA384

        self.assertEqual(state.prf_name, "sha384")

    def test_prf_size_with_sha256(self):
        state = ConnectionState()
        state.cipher = constants.CipherSuite.TLS_AES_128_GCM_SHA256

        self.assertEqual(state.prf_size, 32)

    def test_prf_size_with_sha384(self):
        state = ConnectionState()
        state.cipher = constants.CipherSuite.TLS_AES_256_GCM_SHA384

        self.assertEqual(state.prf_size, 48)


class TestRunner(unittest.TestCase):
    def test___init__(self):
        runner = Runner(None)

        self.assertIsNotNone(runner.state)

    def test_run_with_unknown_type(self):
        node = mock.MagicMock()
        node.is_command = mock.Mock(return_value=False)
        node.is_expect = mock.Mock(return_value=False)
        node.is_generator = mock.Mock(return_value=False)
        node.child = None

        runner = Runner(node)

        with self.assertRaises(AssertionError):
            runner.run()

    def test_run_with_command_node(self):
        node = mock.MagicMock()
        node.is_command = mock.Mock(return_value=True)
        node.is_expect = mock.Mock(return_value=False)
        node.is_generator = mock.Mock(return_value=False)
        node.child = None

        runner = Runner(node)

        runner.run()

        node.process.assert_called_once_with(runner.state)

    def test_run_with_generator_node(self):
        node = mock.MagicMock()
        node.is_command = mock.Mock(return_value=False)
        node.is_expect = mock.Mock(return_value=False)
        node.is_generator = mock.Mock(return_value=True)
        node.child = None
        msg = mock.MagicMock()
        msg.write = mock.Mock(return_value=bytearray(b'\x01\x00'))
        node.generate = mock.Mock(return_value=msg)

        runner = Runner(node)

        runner.state.msg_sock = mock.MagicMock()

        runner.run()

        node.generate.assert_called_once_with(runner.state)
        self.assertTrue(runner.state.msg_sock.sendMessageBlocking.called)
        runner.state.msg_sock.sendMessageBlocking.assert_called_once_with(msg)
        node.post_send.assert_called_once_with(runner.state)

    def test_run_with_zero_generator_node(self):
        node = mock.MagicMock()
        node.is_command = mock.Mock(return_value=False)
        node.is_expect = mock.Mock(return_value=False)
        node.is_generator = mock.Mock(return_value=True)
        node.child = None
        msg = mock.MagicMock()
        msg.write = mock.Mock(return_value=bytearray(b''))
        node.generate = mock.Mock(return_value=msg)

        runner = Runner(node)

        runner.state.msg_sock = mock.MagicMock()

        runner.run()

        node.generate.assert_called_once_with(runner.state)
        self.assertFalse(runner.state.msg_sock.sendMessageBlocking.called)
        self.assertTrue(runner.state.msg_sock.sendRecord.called)
        runner.state.msg_sock.sendRecord.assert_called_once_with(msg)
        node.post_send.assert_called_once_with(runner.state)

    def test_run_with_expect_node(self):
        node = mock.MagicMock()
        node.is_command = mock.Mock(return_value=False)
        node.is_expect = mock.Mock(return_value=True)
        node.is_generator = mock.Mock(return_value=False)
        node.get_all_siblings = mock.Mock(return_value=[node])
        node.is_match = mock.Mock(return_value=True)
        node.child = None

        runner = Runner(node)
        runner.state.msg_sock = mock.MagicMock()
        msg = (mock.MagicMock(name="header"), mock.MagicMock(name="parser"))
        runner.state.msg_sock.recvMessageBlocking = mock.Mock(return_value=msg)

        runner.run()

        internal_message = messages.Message(msg[0].type, msg[1].bytes)

        node.is_match.called_once_with(internal_message)
        node.process.called_once_with(runner.state, internal_message)

    def test_run_with_expect_and_closed_socket(self):
        node = ExpectClose()

        runner = Runner(node)
        runner.state.msg_sock = mock.MagicMock()
        runner.state.msg_sock.recvMessageBlocking = \
                mock.MagicMock(side_effect=TLSAbruptCloseError())

        runner.run()

    def test_run_with_expect_and_unexpected_closed_socket(self):
        node = mock.MagicMock()
        node.is_command = mock.Mock(return_value=False)
        node.is_expect = mock.Mock(return_value=True)
        node.is_generator = mock.Mock(return_value=False)
        node.child = None

        runner = Runner(node)
        runner.state.msg_sock = mock.MagicMock()
        runner.state.msg_sock.recvMessageBlocking = \
                mock.MagicMock(side_effect=TLSAbruptCloseError())

        with self.assertRaises(AssertionError) as e:
            runner.run()

        self.assertIn("Unexpected closure from peer", str(e.exception))

    def test_run_with_expect_and_read_timeout(self):
        node = mock.MagicMock()
        node.is_command = mock.Mock(return_value=False)
        node.is_expect = mock.Mock(return_value=True)
        node.is_generator = mock.Mock(return_value=False)
        node.child = None

        runner = Runner(node)
        runner.state.msg_sock = mock.MagicMock()
        runner.state.msg_sock.recvMessageBlocking = \
                mock.MagicMock(side_effect=socket.timeout())

        with self.assertRaises(AssertionError) as e:
            runner.run()

        self.assertIn("Timeout when waiting", str(e.exception))

    def test_run_with_expect_and_no_message(self):
        node = ExpectNoMessage()

        runner = Runner(node)
        runner.state.msg_sock = mock.MagicMock()
        runner.state.msg_sock.recvMessageBlocking = \
                mock.MagicMock(side_effect=socket.timeout)

        runner.run()

    def test_run_with_expect_no_message_and_message_received(self):
        node = ExpectNoMessage()

        runner = Runner(node)
        runner.state.msg_sock = mock.MagicMock()
        runner.state.msg_sock.recvMessageBlocking = \
                mock.MagicMock(return_value=(mock.MagicMock(),
                                             mock.MagicMock()))

        with self.assertRaises(AssertionError):
            runner.run()

    def test_run_with_expect_node_and_unexpected_message(self):
        node = mock.MagicMock()
        node.is_command = mock.Mock(return_value=False)
        node.is_expect = mock.Mock(return_value=True)
        node.is_generator = mock.Mock(return_value=False)
        node.get_all_siblings = mock.Mock(return_value=[node])
        node.is_match = mock.Mock(return_value=False)
        node.child = None

        runner = Runner(node)
        runner.state.msg_sock = mock.MagicMock()
        msg = (mock.MagicMock(name="header"), mock.MagicMock(name="parsser"))
        runner.state.msg_sock.recvMessageBlocking = \
                mock.MagicMock(return_value=msg)

        with self.assertRaises(AssertionError):
            runner.run()

        runner.state.msg_sock.sock.close.called_once_with()

    def test_run_with_generate_and_unexpected_closed_socket(self):
        node = mock.MagicMock()
        node.is_command = mock.Mock(return_value=False)
        node.is_expect = mock.Mock(return_value=False)
        node.is_generator = mock.Mock(return_value=True)
        node.child = None

        runner = Runner(node)
        runner.state.msg_sock = mock.MagicMock()
        runner.state.msg_sock.sendMessageBlocking = \
                mock.MagicMock(side_effect=socket.error)

        with self.assertRaises(AssertionError):
            runner.run()

    def test_run_with_generate_and_expected_closed_socket(self):
        node = ClientHelloGenerator()
        node.next_sibling = ExpectClose()

        runner = Runner(node)
        runner.state.msg_sock = mock.MagicMock()
        runner.state.msg_sock.sendMessageBlocking = \
                mock.MagicMock(side_effect=socket.error)

        # does NOT raise exception
        runner.run()

class TestGuessResponse(unittest.TestCase):

    def test_guess_response(self):
        content_type = constants.ContentType.application_data
        data = bytearray(10)

        self.assertEqual("ApplicationData(len=10)",
                         guess_response(content_type, data))

    def test_guess_response_with_CCS(self):
        content_type = constants.ContentType.change_cipher_spec
        data = bytearray(b'\x01')

        self.assertEqual("ChangeCipherSpec()",
                         guess_response(content_type, data))

    def test_guess_response_with_bad_CCS(self):
        content_type = constants.ContentType.change_cipher_spec
        data = bytearray()

        self.assertEqual("ChangeCipherSpec(invalid size)",
                         guess_response(content_type, data))

    def test_guess_response_with_alert(self):
        content_type = constants.ContentType.alert
        data = bytearray([constants.AlertLevel.warning,
                          constants.AlertDescription.protocol_version])

        self.assertEqual("Alert(warning, protocol_version)",
                         guess_response(content_type, data))

    def test_guess_response_with_invalid_alert(self):
        content_type = constants.ContentType.alert
        data = bytearray([constants.AlertLevel.warning])

        self.assertEqual("Alert(invalid size)",
                         guess_response(content_type, data))

    def test_guess_response_with_handshake(self):
        content_type = constants.ContentType.handshake
        data = bytearray([constants.HandshakeType.client_hello,
                          0, 0, 0])

        self.assertEqual("Handshake(client_hello)",
                         guess_response(content_type, data))
    def test_guess_response_with_invalid_handshake(self):
        content_type = constants.ContentType.handshake
        data = bytearray()

        self.assertEqual("Handshake(invalid size)",
                         guess_response(content_type, data))

    def test_guess_response_with_invalid_data(self):
        content_type = 0xfa
        data = bytearray(b'\x02\x03\x05')

        self.assertEqual("Message(content_type=250, first_byte=2, len=3)",
                         guess_response(content_type, data))

    def test_guess_response_with_SSL2_hanshake(self):
        content_type = constants.ContentType.handshake
        data = bytearray([constants.SSL2HandshakeType.server_hello])

        self.assertEqual("Handshake(server_hello)",
                         guess_response(content_type, data, ssl2=True))
