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
from tlsfuzzer.expect import ExpectClose
import tlslite.messages as messages
import tlslite.constants as constants
from tlslite.errors import TLSAbruptCloseError

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
        cert_list = mock.MagicMock()
        msg.create(cert_list)

        state.handshake_messages.append(msg)

        state.get_server_public_key()
        self.assertTrue(cert_list.getEndEntityPublicKey.called)

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

        runner = Runner(node)

        runner.state.msg_sock = mock.MagicMock()

        runner.run()

        node.generate.assert_called_once_with(runner.state)
        self.assertTrue(runner.state.msg_sock.sendMessageBlocking.called)
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
