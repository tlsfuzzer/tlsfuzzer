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

import socket
import os

from tlsfuzzer.messages import ClientHelloGenerator, ClientKeyExchangeGenerator,\
        ChangeCipherSpecGenerator, FinishedGenerator, \
        RenegotiationInfoExtension, ResetHandshakeHashes, SetMaxRecordSize, \
        pad_handshake, truncate_handshake, Close, fuzz_message, \
        RawMessageGenerator, split_message, PopMessageFromList, \
        FlushMessageList, fuzz_mac, fuzz_padding, ApplicationDataGenerator, \
        CertificateGenerator, CertificateVerifyGenerator, CertificateRequest, \
        ResetRenegotiationInfo, fuzz_plaintext, Connect, \
        ClientMasterKeyGenerator, TCPBufferingEnable, TCPBufferingDisable, \
        TCPBufferingFlush, fuzz_encrypted_message, fuzz_pkcs1_padding, \
        CollectNonces, AlertGenerator, PlaintextMessageGenerator, \
        SetPaddingCallback, replace_plaintext, ch_cookie_handler, \
        ch_key_share_handler, SetRecordVersion, CopyVariables, \
        ResetWriteConnectionState, HeartbeatGenerator, Certificate, \
        KeyUpdateGenerator, ClearContext, RawSocketWriteGenerator
from tlsfuzzer.helpers import psk_ext_gen, psk_ext_updater, \
        psk_session_ext_gen, AutoEmptyExtension
from tlsfuzzer.runner import ConnectionState
import tlslite.messages as messages
import tlslite.messagesocket as messagesocket
import tlslite.extensions as extensions
from tlslite.handshakehashes import HandshakeHashes
from tlslite.keyexchange import KeyExchange
import tlslite.utils.keyfactory as keyfactory
from tlslite.utils.cryptomath import bytesToNumber, numberToByteArray, \
        secureHash
from tlsfuzzer.utils.ordered_dict import OrderedDict
import tlslite.constants as constants
import tlslite.defragmenter as defragmenter
from tlslite.utils.codec import Parser
from tests.mocksock import MockSocket
from tlslite.utils.keyfactory import generateRSAKey
from tlslite.utils.cryptomath import numberToByteArray
from tlslite.utils.python_rsakey import Python_RSAKey
from tlslite.utils.python_ecdsakey import Python_ECDSAKey
from tlslite.utils.python_eddsakey import Python_EdDSAKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain
from ecdsa import SigningKey, Ed25519


rsa_pss_cert = X509CertChain([X509().parse(
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDWzCCAhKgAwIBAgIJAM94DjB2Qf+GMD4GCSqGSIb3DQEBCjAxoA0wCwYJYIZI\n"
    "AWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIEAgIA3jAUMRIwEAYD\n"
    "VQQDDAlsb2NhbGhvc3QwHhcNMTcwMzA4MTMzMzU4WhcNMTcwNDA3MTMzMzU4WjAU\n"
    "MRIwEAYDVQQDDAlsb2NhbGhvc3QwggEgMAsGCSqGSIb3DQEBCgOCAQ8AMIIBCgKC\n"
    "AQEApq5FnZRNmtJy+WjNRB8w0ol2+IEcATrUkZpz7HNqq8+EL/GN21m35luz5fcA\n"
    "8ifkm4pKxfwtxY7u912tAfsEavUr/UoyLScXQevhr6SLXR8UO3XE6ne1F88eZNpg\n"
    "KVpocDVKRLjIqKHSSbBNkG76mGKFYyNZXm3qRxaUSHVLnN/opOGfgVK8Vbj0v2EH\n"
    "5L5dGLQLV2ZfQ75I4OGrg8wse5fhgt2oczhhe72sEuMDc08WHGRp9744mMQvVYrt\n"
    "pWUHkP5tdD4i7/zYf3nig21/G56JY20JpW+1J5fEn+PEqiJsv5prNJuPp/zdjD3u\n"
    "ImqfXZzXUeRIQr9l1qXI6JPInwIDAQABo1AwTjAdBgNVHQ4EFgQUcTYhLu7pODIv\n"
    "B6KhR6eyFBB5wacwHwYDVR0jBBgwFoAUcTYhLu7pODIvB6KhR6eyFBB5wacwDAYD\n"
    "VR0TBAUwAwEB/zA+BgkqhkiG9w0BAQowMaANMAsGCWCGSAFlAwQCAaEaMBgGCSqG\n"
    "SIb3DQEBCDALBglghkgBZQMEAgGiBAICAN4DggEBAKMgweHM6WTwlWEQHLG5K+7B\n"
    "hrAUEAsuK8F7sKGKzLEFzYdzZpkJw8LahE4dFayjx/7MD4rZ5IiHQhJcGCdHIVVv\n"
    "ocunlEUTgiKkMxTw4JxqSq0snvNBie04vnn+zUjD7FrctTUutzlH1yKftwbJpGk6\n"
    "CrTW6ctFTAIDwZHd+WX4RPewGY0LTfC+RjcMwWZBmbfVLxuJs0sidSUoNW6GgGE1\n"
    "DIDVeW2yKGeNhjK/3aDzfQWbz1J64aRfccVzXYMPsoABnNJnJgRETh1/Ci0sQ9Vd\n"
    "1OR6iS4hl88/1d7utc00MyFVk1sUIGf54EeCvrNB4bhKtawEJk8Q8AGIRhs93sk=\n"
    "-----END CERTIFICATE-----\n")])


ecdsa_cert = X509CertChain([X509().parse(
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBbTCCARSgAwIBAgIJAPM58cskyK+yMAkGByqGSM49BAEwFDESMBAGA1UEAwwJ\n"
    "bG9jYWxob3N0MB4XDTE3MTAyMzExNDI0MVoXDTE3MTEyMjExNDI0MVowFDESMBAG\n"
    "A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyDRjEAJe\n"
    "3F5T62MyZbhjoJnPLGL2nrTthLFymBupZ2IbnWYnqVWDkT/L6i8sQhf2zCLrlSjj\n"
    "1kn7ERqPx/KZyqNQME4wHQYDVR0OBBYEFPfFTUg9o3t6ehLsschSnC8Te8oaMB8G\n"
    "A1UdIwQYMBaAFPfFTUg9o3t6ehLsschSnC8Te8oaMAwGA1UdEwQFMAMBAf8wCQYH\n"
    "KoZIzj0EAQNIADBFAiA6p0YM5ZzfW+klHPRU2r13/IfKgeRfDR3dtBngmPvxUgIh\n"
    "APTeSDeJvYWVBLzyrKTeSerNDKKHU2Rt7sufipv76+7s\n"
    "-----END CERTIFICATE-----\n"
    )])


ecdsa_key = keyfactory.parsePEMKey(
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCOZr0Ovs0eCmh+XM\n"
    "QWDYVpsQ+sJdjiq/itp/kYnWNSahRANCAATINGMQAl7cXlPrYzJluGOgmc8sYvae\n"
    "tO2EsXKYG6lnYhudZiepVYORP8vqLyxCF/bMIuuVKOPWSfsRGo/H8pnK\n"
    "-----END PRIVATE KEY-----\n",
    private=True)


class TestClose(unittest.TestCase):
    def test___init__(self):
        close = Close()

        self.assertIsNotNone(close)

    def test_process(self):
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        close = Close()
        close.process(state)

        state.msg_sock.sock.close.called_once_with()

class TestTCPBufferingEnable(unittest.TestCase):
    def test___init__(self):
        node = TCPBufferingEnable()

        self.assertIsNotNone(node)
        self.assertTrue(node.is_command())
        self.assertFalse(node.is_expect())
        self.assertFalse(node.is_generator())

    @mock.patch('socket.socket')
    def test_generate(self, raw_sock):
        state = ConnectionState()
        conn = Connect('localhost', 4433)
        conn.process(state)

        self.assertFalse(state.msg_sock.sock.buffer_writes)

        node = TCPBufferingEnable()
        node.process(state)

        self.assertTrue(state.msg_sock.sock.buffer_writes)

class TestTCPBufferingDisable(unittest.TestCase):
    def test___init__(self):
        node = TCPBufferingDisable()

        self.assertIsNotNone(node)
        self.assertTrue(node.is_command())
        self.assertFalse(node.is_expect())
        self.assertFalse(node.is_generator())

    @mock.patch('socket.socket')
    def test_generate(self, raw_sock):
        state = ConnectionState()
        conn = Connect('localhost', 4433)
        conn.process(state)

        self.assertFalse(state.msg_sock.sock.buffer_writes)

        node = TCPBufferingEnable()
        node.process(state)

        self.assertTrue(state.msg_sock.sock.buffer_writes)

        node = TCPBufferingDisable()
        node.process(state)

        self.assertFalse(state.msg_sock.sock.buffer_writes)


class TestTCPBufferingFlush(unittest.TestCase):
    def test___init__(self):
        node = TCPBufferingFlush()

        self.assertIsNotNone(node)
        self.assertTrue(node.is_command())
        self.assertFalse(node.is_expect())
        self.assertFalse(node.is_generator())

    @mock.patch('socket.socket')
    def test_generate(self, raw_sock):
        state = ConnectionState()
        conn = Connect('localhost', 4433)
        conn.process(state)

        node = TCPBufferingEnable()
        node.process(state)

        node = RawMessageGenerator(12, bytearray(b'\xff'))
        msg = node.generate(state)
        state.msg_sock.sendMessageBlocking(msg)

        raw_sock.return_value.send.assert_not_called()
        raw_sock.return_value.sendall.assert_not_called()

        flush = TCPBufferingFlush()
        flush.process(state)

        raw_sock.return_value.sendall.assert_called_once_with(
                bytearray(b'\x0c\x03\x00\x00\x01\xff'))


class TestResetWriteConnectionState(unittest.TestCase):
    def test__init__(self):
        node = ResetWriteConnectionState()

        self.assertIsNotNone(node)
        self.assertTrue(node.is_command())
        self.assertFalse(node.is_expect())
        self.assertFalse(node.is_generator())

    def test_process(self):
        state = ConnectionState()
        socket = MockSocket(bytearray())

        defragger = defragmenter.Defragmenter()
        defragger.add_static_size(constants.ContentType.alert, 2)
        defragger.add_static_size(constants.ContentType.change_cipher_spec, 1)
        defragger.add_dynamic_size(constants.ContentType.handshake, 1, 3)
        state.msg_sock = messagesocket.MessageSocket(socket,
                                                     defragger)

        state.msg_sock.version = (3, 3)
        state.msg_sock.encryptThenMAC = True
        state.msg_sock.calcPendingStates(
                constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                bytearray(48),
                bytearray(32),
                bytearray(32),
                None)
        state.msg_sock.changeWriteState()
        state.msg_sock.changeReadState()

        self.assertIsNotNone(state.msg_sock._writeState.macContext)
        self.assertIsNotNone(state.msg_sock._writeState.encContext)
        self.assertTrue(state.msg_sock._writeState.encryptThenMAC)

        node = ResetWriteConnectionState()
        node.process(state)

        self.assertIsNotNone(state.msg_sock._readState.macContext)
        self.assertIsNotNone(state.msg_sock._readState.encContext)
        self.assertTrue(state.msg_sock._readState.encryptThenMAC)

        self.assertIsNone(state.msg_sock._writeState.macContext)
        self.assertIsNone(state.msg_sock._writeState.encContext)
        self.assertIsNone(state.msg_sock._writeState.fixedNonce)
        self.assertEqual(state.msg_sock._writeState.seqnum, 0)
        self.assertFalse(state.msg_sock._writeState.encryptThenMAC)


class TestCollectNonces(unittest.TestCase):
    def test__init__(self):
        nonces = []
        node = CollectNonces(nonces)

        self.assertTrue(node.is_command())

    def test_process(self):
        state = ConnectionState()

        sock = MockSocket(bytearray())

        defragger = defragmenter.Defragmenter()
        defragger.add_static_size(constants.ContentType.alert, 2)
        defragger.add_static_size(constants.ContentType.change_cipher_spec, 1)
        defragger.add_dynamic_size(constants.ContentType.handshake, 1, 3)
        state.msg_sock = messagesocket.MessageSocket(sock,
                                                     defragger)


        state.msg_sock.version = (3, 3)
        state.msg_sock.calcPendingStates(constants.CipherSuite.
                                         TLS_RSA_WITH_AES_128_GCM_SHA256,
                                         bytearray(48),
                                         bytearray(32),
                                         bytearray(32),
                                         None)
        state.msg_sock.changeWriteState()

        nonces = []
        node = CollectNonces(nonces)
        node.process(state)

        node = ApplicationDataGenerator(b'some text')
        msg = node.generate(state)
        state.msg_sock.sendMessageBlocking(msg)

        self.assertEqual(nonces,
                         [bytearray(b'\xa9\xfc\x88\x1d'
                                    b'\x00\x00\x00\x00\x00\x00\x00\x00')])


class TestCopyVariables(unittest.TestCase):
    def test___init__(self):
        node = CopyVariables({})

        self.assertIsNotNone(node)
        self.assertTrue(node.is_command())
        self.assertFalse(node.is_expect())
        self.assertFalse(node.is_generator())

    def test_process_client_hello_random(self):
        state = ConnectionState()
        state.client_random = bytearray(b'test')

        arr = []
        node = CopyVariables({'ClientHello.random': arr})

        node.process(state)

        self.assertEqual(arr, [bytearray(b'test')])

    def test_process_server_hello_random(self):
        state = ConnectionState()
        state.server_random = bytearray(b'abba')

        arr = []
        node = CopyVariables({'ServerHello.random': arr})

        node.process(state)

        self.assertEqual(arr, [bytearray(b'abba')])

    def test_process_server_hello_session_id(self):
        state = ConnectionState()
        state.session_id = bytearray(b'some session ID')

        arr = []
        node = CopyVariables({'ServerHello.session_id': arr})

        node.process(state)

        self.assertEqual(arr, [bytearray(b'some session ID')])

    def test_process_premaster_secret(self):
        state = ConnectionState()
        state.key['premaster_secret'] = bytearray(b'premaster secret')

        arr = []
        node = CopyVariables({'premaster_secret': arr})

        node.process(state)

        self.assertEqual(arr, [bytearray(b'premaster secret')])

    def test_process_with_incorrect_name(self):
        state = ConnectionState()

        arr = []
        node = CopyVariables({'DH shared secret': arr})

        with self.assertRaises(ValueError):
            node.process(state)


class TestConnect(unittest.TestCase):
    def test___init__(self):
        connect = Connect(1, 2)

        self.assertIsNotNone(connect)
        self.assertEqual(connect.hostname, 1)
        self.assertEqual(connect.port, 2)
        self.assertEqual(connect.version, (3, 0))
        self.assertEqual(connect.timeout, 5)

    @mock.patch('socket.socket')
    def test_process(self, mock_sock):
        state = ConnectionState()
        connect = Connect("localhost", 4433)

        connect.process(state)

        self.assertEqual(state.msg_sock.version, (3, 0))

        mock_sock.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        instance = mock_sock.return_value
        instance.connect.assert_called_once_with(("localhost", 4433))
        self.assertIs(state.msg_sock.sock.socket, instance)

    @mock.patch('socket.socket')
    def test_process_with_SSLv2(self, mock_sock):
        state = ConnectionState()
        connect = Connect(1, 2, (0, 2))

        connect.process(state)

        self.assertEqual(state.msg_sock.version, (0, 2))

        mock_sock.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        instance = mock_sock.return_value
        instance.connect.assert_called_once_with((1, 2))
        self.assertIs(state.msg_sock.sock.socket, instance)

    @mock.patch('socket.socket')
    def test_process_with_timeout(self, mock_sock):
        state = ConnectionState()
        connect = Connect(1, 2, timeout=10)

        connect.process(state)

        mock_sock.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        instance = mock_sock.return_value
        instance.connect.assert_called_once_with((1, 2))
        instance.settimeout.assert_called_once_with(10)
        self.assertIs(state.msg_sock.sock.socket, instance)


class TestSetRecordVersion(unittest.TestCase):
    def test___init__(self):
        msg_gen = SetRecordVersion((3, 3))

        self.assertIsNotNone(msg_gen)
        self.assertTrue(msg_gen.is_command())
        self.assertFalse(msg_gen.is_expect())
        self.assertFalse(msg_gen.is_generator())

    def test_process(self):
        msg_gen = SetRecordVersion((3, 2))

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        msg_gen.process(state)

        self.assertEqual(state.msg_sock.version, (3, 2))


class TestRawSocketWriteGenerator(unittest.TestCase):
    def test___init__(self):
        msg_gen = RawSocketWriteGenerator(bytearray(b'some data'))

        self.assertIsNotNone(msg_gen)
        self.assertTrue(msg_gen.is_command())
        self.assertFalse(msg_gen.is_expect())
        self.assertFalse(msg_gen.is_generator())

    def test___repr__(self):
        msg_gen = RawSocketWriteGenerator(bytearray(b'some data'))

        self.assertEqual(repr(msg_gen),
                         "RawSocketWriteGenerator(data=bytearray(b'some data'))")

    def test___repr___with_description(self):
        msg_gen = RawSocketWriteGenerator(bytearray(b'some data'),
                                          description="STARTTLS")

        self.assertEqual(repr(msg_gen),
                         "RawSocketWriteGenerator("
                         "data=bytearray(b'some data'), "
                         "description='STARTTLS')")

    def test_process(self):
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        msg_gen = RawSocketWriteGenerator(b'some data')

        msg_gen.process(state)

        self.assertTrue(
            state.msg_sock._recordSocket.
            sock.send.called_once_with(b'some data'))


class TestPlaintextMessageGenerator(unittest.TestCase):
    def test___init__(self):
        msg_gen = PlaintextMessageGenerator(12, bytearray(b'\x00\x00'))

        self.assertIsNotNone(msg_gen)
        self.assertTrue(msg_gen.is_command())
        self.assertFalse(msg_gen.is_expect())
        self.assertFalse(msg_gen.is_generator())

    def test___repr__(self):
        msg_gen = PlaintextMessageGenerator(12, bytearray(b'\x00\x00'))

        self.assertEqual(repr(msg_gen),
                         "PlaintextMessageGenerator(content_type=12, "
                         "data=bytearray(b'\\x00\\x00'))")

    def test___repr___with_description(self):
        msg_gen = PlaintextMessageGenerator(12, bytearray(b'\x00\x00'),
                                            description="some message")

        self.assertEqual(repr(msg_gen),
                         "PlaintextMessageGenerator(content_type=12, "
                         "data=bytearray(b'\\x00\\x00'), "
                         "description='some message')")

    def test_process(self):
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        msg_gen = PlaintextMessageGenerator(12, bytearray(b'\x00\x00'))

        msg_gen.process(state)

        self.assertTrue(state.msg_sock._recordSocket.send.called)


class TestRawMessageGenerator(unittest.TestCase):
    def test___init__(self):
        message_gen = RawMessageGenerator(12, bytearray(b'\xff\x02'))

        self.assertIsNotNone(message_gen)
        self.assertEqual(message_gen.content_type, 12)
        self.assertEqual(message_gen.data, bytearray(b'\xff\x02'))

    def test_gen(self):
        message_gen = RawMessageGenerator(12, bytearray(b'\xff\x02'))

        message = message_gen.generate(None)

        self.assertIsNotNone(message)
        self.assertEqual(message.contentType, 12)
        self.assertEqual(message.write(), bytearray(b'\xff\x02'))

    def test___repr__(self):
        message_gen = RawMessageGenerator(12, bytearray(b'\xff\x02'))

        self.assertEqual(repr(message_gen),
                         "RawMessageGenerator(content_type=12, "\
                         "data=bytearray(b'\\xff\\x02'))")

    def test___repr___with_description(self):
        message_gen = RawMessageGenerator(12, bytearray(b'\xff'),
                                          description="a broken message")

        self.assertEqual(repr(message_gen),
                         "RawMessageGenerator(content_type=12, "\
                         "data=bytearray(b'\\xff'), description='a broken "\
                         "message')")

class TestClientHelloGenerator(unittest.TestCase):
    def test___init__(self):
        chg = ClientHelloGenerator()

        self.assertIsNotNone(chg)
        self.assertEqual(chg.ciphers, [])

    def test___repr__(self):
        chg = ClientHelloGenerator()
        chg.compression = []

        self.assertEqual("ClientHelloGenerator()", repr(chg))

    def test___repr___with_values(self):
        chg = ClientHelloGenerator(
            [2, 3], ["ext"], (3, 3), bytearray(b'sess'), bytearray(b'random'),
            [0xc0], True, ["mod"])

        self.assertEqual(
            "ClientHelloGenerator("
            "ssl2=True, "
            "version=(3, 3), "
            "ciphers=[2, 3], "
            "random=bytearray(b'random'), "
            "session_id=bytearray(b'sess'), "
            "compression=[192], "
            "extensions=['ext'], "
            "modifiers=['mod'])",
            repr(chg))

    def test_generate(self):
        state = ConnectionState()
        chg = ClientHelloGenerator()

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)
        mock_method.assert_called_once_with((3, 3), bytearray(32), bytearray(0),
                                            [], extensions=None)

    def test_generate_extensions_with_missing_generator(self):
        state = ConnectionState()
        chg = ClientHelloGenerator(extensions={0x1234:None})

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with self.assertRaises(ValueError):
            with mock.patch.object(messages.ClientHello, 'create',
                    return_value=return_val) as mock_method:
                chg.generate(state)

    def test_generate_extensions_with_auto_generator(self):
        state = ConnectionState()
        chg = ClientHelloGenerator(extensions={0x1234: AutoEmptyExtension()})

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)
        ext = extensions.TLSExtension().create(0x1234, bytearray(0))
        mock_method.assert_called_once_with((3, 3), bytearray(32),
                                            bytearray(0), [], extensions=[ext])

    def test_generate_extensions_with_raw_extension(self):
        state = ConnectionState()
        ext = extensions.TLSExtension().create(extType=0x1234, data=None)
        chg = ClientHelloGenerator(extensions={0x1234:ext})

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)
        mock_method.assert_called_once_with((3, 3), bytearray(32), bytearray(0),
                                            [],
                                            extensions=[ext])

    def test_generate_extensions_with_garbage_extension(self):
        state = ConnectionState()
        ext = "some weird non-extension"
        chg = ClientHelloGenerator(extensions={0x1234:ext})

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                return_value=return_val) as mock_method:
            with self.assertRaises(ValueError):
                ch = chg.generate(state)

    def test_generate_extensions_with_ext_generator(self):
        state = ConnectionState()
        ext_gen = mock.MagicMock()
        chg = ClientHelloGenerator(extensions={0x1234:ext_gen})

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)

        ext_gen.assert_called_once_with(state)
        mock_method.assert_called_once_with((3, 3), bytearray(32), bytearray(0),
                                            [],
                                            extensions=[ext_gen()])

    def test_generate_extensions_with_automatic_status_request(self):
        state = ConnectionState()
        chg = ClientHelloGenerator(extensions=
            {constants.ExtensionType.status_request: None})

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)

        mock_method.assert_called_once_with(
            (3, 3), bytearray(32), bytearray(0),
            [],
            extensions=[extensions.StatusRequestExtension().create()])

    def test_generate_extensions_with_automatic_encrypt_then_mac(self):
        state = ConnectionState()
        chg = ClientHelloGenerator(extensions=
            {constants.ExtensionType.encrypt_then_mac: None})

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)

        mock_method.assert_called_once_with(
            (3, 3), bytearray(32), bytearray(0),
            [],
            extensions=[extensions.TLSExtension(extType=22).create(b'')])

    def test_generate_extensions_with_renego_info_default_generator(self):
        state = ConnectionState()
        state.key['client_verify_data'] = bytearray(b'\xab\xcd')
        chg = ClientHelloGenerator(extensions={constants.ExtensionType.renegotiation_info:
                                               None})

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)

        ext = RenegotiationInfoExtension().create(bytearray(b'\xab\xcd'))
        mock_method.assert_called_once_with((3, 3), bytearray(32), bytearray(0),
                                            [],
                                            extensions=[ext])

    def test_generate_with_random(self):
        state = ConnectionState()
        chg = ClientHelloGenerator(random=bytearray(b'\x33'*32))

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                               return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)
        mock_method.assert_called_once_with((3, 3), bytearray(b'\x33'*32),
                                            bytearray(0), [], extensions=None)

    def test_generate_with_compression_methods(self):
        state = ConnectionState()
        chg = ClientHelloGenerator(compression=[0, 2, 3])

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                               return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)
        self.assertEqual(ch.compression_methods, [0, 2, 3])
        mock_method.assert_called_once_with((3, 3), bytearray(32),
                                            bytearray(0), [], extensions=None)

    def test_session_id_with_no_settings(self):
        state = ConnectionState()
        chg = ClientHelloGenerator(version=(3, 4))

        msg = chg.generate(state)

        self.assertEqual(msg.session_id, b'')

    def test_seesion_id_with_tls13_extension(self):
        state = ConnectionState()
        exts = {constants.ExtensionType.supported_versions:
                AutoEmptyExtension()}
        chg = ClientHelloGenerator(version=(3, 3), extensions=exts)

        msg = chg.generate(state)

        self.assertEqual(len(msg.session_id), 32)

    def test_session_id_with_explicit_id_and_tls13_extension(self):
        state = ConnectionState()
        exts = {constants.ExtensionType.supported_versions:
                AutoEmptyExtension()}
        chg = ClientHelloGenerator(version=(3, 3), extensions=exts,
                                   session_id=b'')

        msg = chg.generate(state)

        self.assertEqual(msg.session_id, b'')

    def test_modifiers(self):
        state = ConnectionState()
        psk_configs = [(b'test', b'secret')]
        exts = OrderedDict()
        exts[constants.ExtensionType.supported_versions] = \
            AutoEmptyExtension()
        exts[constants.ExtensionType.pre_shared_key] = \
            psk_ext_gen(psk_configs)
        modifiers = [psk_ext_updater(psk_configs)]
        chg = ClientHelloGenerator(version=(3, 3), extensions=exts,
                                   session_id=b'\xaa'*32,
                                   modifiers=modifiers)

        msg = chg.generate(state)

        self.assertEqual(len(msg.extensions), 2)
        self.assertIsInstance(msg.extensions[1],
                              extensions.PreSharedKeyExtension)
        ext = msg.extensions[1]
        self.assertEqual(len(ext.binders), 1)
        self.assertEqual(
            ext.binders[0],
            bytearray(b"\x04!\xd0\xee\x0c\xe8\x13W\xa9\x85\xcc\xce\x07U\x87"
                      b"\xe6\'\xfa\xec\xf4\xf7\x88\x8b\xf3\xc2\xc3^\xf3<\x8b"
                      b"\xba%"))

    def test_with_session_tickets(self):
        state = ConnectionState()
        state.key['resumption master secret'] = bytearray(b'\x10' * 48)
        state.cipher = constants.CipherSuite.TLS_AES_256_GCM_SHA384
        state.session_tickets = [
            messages.NewSessionTicket().create(
                101, 0, bytearray(b'some nonce'),
                bytearray(b'ticket identity'), [])]
        state.session_tickets[0].time = 12.12
        exts = OrderedDict()
        exts[constants.ExtensionType.supported_versions] = \
            AutoEmptyExtension()
        exts[constants.ExtensionType.pre_shared_key] = \
            psk_session_ext_gen()
        modifiers = [psk_ext_updater()]
        chg = ClientHelloGenerator(version=(3, 3), extensions=exts,
                                   session_id=b'\xaa'*32,
                                   modifiers=modifiers)

        with mock.patch('time.time') as mthd:
            mthd.return_value = 1532009672.427739153
            msg = chg.generate(state)

        self.assertEqual(len(msg.extensions), 2)
        self.assertIsInstance(msg.extensions[1],
                              extensions.PreSharedKeyExtension)
        ext = msg.extensions[1]
        self.assertEqual(len(ext.binders), 1)
        self.assertEqual(
            ext.binders[0],
            bytearray(b'6f&\xe42^a\x13\x949\xc3Q\xb0\x1fD\xb6H\xba\xc1=D\xa6'
                      b'\xcb1\x05\xd72\x1eKO\x8d\xf9V\xa13\xdc\x94b\xdb\xc6'
                      b'\x92\\\xe9\xd2\xd7Tv\xb2'))


class TestClientHelloExtensionGenerators(unittest.TestCase):
    def setUp(self):
        self.state = ConnectionState()

        exts = [extensions.CookieExtension().create(b'some payload'),
                extensions.HRRKeyShareExtension().create(
                    constants.GroupName.secp256r1)]

        hrr = messages.ServerHello()
        hrr.create(version=(3, 3),
                   random=constants.TLS_1_3_HRR,
                   session_id=b'',
                   cipher_suite=0x04,
                   extensions=exts)

        self.state.handshake_messages.append(hrr)

    def test_ch_cookie_handler(self):
        ext = ch_cookie_handler(self.state)

        self.assertIsInstance(ext, extensions.CookieExtension)
        self.assertEqual(ext.cookie, b'some payload')

    def test_ch_cookie_handler_with_no_hrr(self):
        self.state.handshake_messages = []

        with self.assertRaises(ValueError) as e:
            ch_cookie_handler(self.state)

        self.assertIn("No HRR received", str(e.exception))

    def test_ch_key_share_handler(self):
        ext = ch_key_share_handler(self.state)

        self.assertIsInstance(ext, extensions.ClientKeyShareExtension)
        self.assertEqual(len(ext.client_shares), 1)
        self.assertIsInstance(ext.client_shares[0], extensions.KeyShareEntry)
        self.assertEqual(ext.client_shares[0].group,
                         constants.GroupName.secp256r1)

    def test_ch_key_share_handler_with_no_hrr(self):
        self.state.handshake_messages = []

        with self.assertRaises(ValueError) as e:
            ch_key_share_handler(self.state)

        self.assertIn("No HRR received", str(e.exception))


class TestClientKeyExchangeGenerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key = keyfactory.generateRSAKey(1024)

    def test___init__(self):
        cke = ClientKeyExchangeGenerator()

        self.assertEqual(len(cke.premaster_secret), 48)

    def test___init___with_invalid_param(self):
        with self.assertRaises(ValueError):
            cke = ClientKeyExchangeGenerator(p_as_share=True,
                                             p_1_as_share=True)

    def test_generate(self):
        state = ConnectionState()
        state.get_server_public_key = lambda : self.priv_key
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)

        ret = cke.generate(state)

        self.assertEqual(len(ret.encryptedPreMasterSecret), 128)
        decrypt = self.priv_key.decrypt(ret.encryptedPreMasterSecret)

        self.assertEqual(decrypt[:2], bytearray([3, 3]))
        self.assertEqual(decrypt[2:], bytearray([0]*46))

    def test_generate_with_custom_premaster_secret(self):
        state = ConnectionState()
        state.get_server_public_key = lambda : self.priv_key
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                premaster_secret=bytearray([1]*10))

        ret = cke.generate(state)

        self.assertEqual(len(ret.encryptedPreMasterSecret), 128)
        decrypt = self.priv_key.decrypt(ret.encryptedPreMasterSecret)

        self.assertEqual(decrypt[:2], bytearray([3, 3]))
        self.assertEqual(decrypt[2:], bytearray([1]*8))

    def test_generate_with_node_reuse_and_no_encrypted_value_reuse(self):
        state = ConnectionState()
        state.get_server_public_key = lambda : self.priv_key
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                premaster_secret=bytearray([1]*10))

        ret = cke.generate(state)

        self.assertEqual(len(ret.encryptedPreMasterSecret), 128)
        decrypt = self.priv_key.decrypt(ret.encryptedPreMasterSecret)

        self.assertEqual(decrypt[:2], bytearray([3, 3]))
        self.assertEqual(decrypt[2:], bytearray([1]*8))

        ret2 = cke.generate(state)
        self.assertNotEqual(ret.encryptedPreMasterSecret,
                            ret2.encryptedPreMasterSecret)

    def test_generate_with_node_reuse_and_encrypted_value_reuse(self):
        state = ConnectionState()
        state.get_server_public_key = lambda : self.priv_key
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                premaster_secret=bytearray([1]*10),
                reuse_encrypted_premaster=True)

        ret = cke.generate(state)

        self.assertEqual(len(ret.encryptedPreMasterSecret), 128)
        decrypt = self.priv_key.decrypt(ret.encryptedPreMasterSecret)

        self.assertEqual(decrypt[:2], bytearray([3, 3]))
        self.assertEqual(decrypt[2:], bytearray([1]*8))

        ret2 = cke.generate(state)
        self.assertEqual(ret.encryptedPreMasterSecret,
                         ret2.encryptedPreMasterSecret)

    def test_generate_with_dhe(self):
        state = ConnectionState()
        state.key_exchange = mock.MagicMock()

        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)

        ret = cke.generate(state)

        self.assertIs(ret, state.key_exchange.makeClientKeyExchange())

    def test_generate_with_ecdhe(self):
        state = ConnectionState()
        state.key_exchange = mock.MagicMock()

        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)

        ret = cke.generate(state)

        self.assertIs(ret, state.key_exchange.makeClientKeyExchange())

    def test_generate_with_unknown_cipher(self):
        state = ConnectionState()
        cke = ClientKeyExchangeGenerator()
        with self.assertRaises(AssertionError):
            cke.generate(state)

    def test_generate_DHE_with_bogus_value(self):
        state = ConnectionState()
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                dh_Yc=4982)

        ret = cke.generate(state)
        self.assertEqual(ret.dh_Yc, 4982)

    def test_generate_ECDHE_with_bogus_value(self):
        state = ConnectionState()
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                ecdh_Yc=bytearray(range(1, 24)))

        ret = cke.generate(state)
        self.assertEqual(ret.ecdh_Yc, bytearray(range(1, 24)))

    def test_generate_with_all_null_RSA(self):
        state = ConnectionState()
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                encrypted_premaster=bytearray(512))

        ret = cke.generate(state)
        self.assertEqual(ret.encryptedPreMasterSecret, bytearray(512))

    def test_generate_with_modulus_as_premaster(self):
        state = ConnectionState()
        state.get_server_public_key = lambda : self.priv_key
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                modulus_as_encrypted_premaster=True)

        ret = cke.generate(state)
        self.assertEqual(ret.encryptedPreMasterSecret,
                         numberToByteArray(self.priv_key.n))

    def test_generate_with_p_as_share(self):
        state = ConnectionState()
        ske = messages.ServerKeyExchange(
                constants.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                (3, 3))
        ske.createDH(21, 2, 11)
        state.handshake_messages.append(ske)
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                p_as_share=True)

        ret = cke.generate(state)
        self.assertEqual(ret.dh_Yc, 21)

    def test_generate_with_p_1_as_share(self):
        state = ConnectionState()
        ske = messages.ServerKeyExchange(
                constants.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                (3, 3))
        ske.createDH(21, 2, 11)
        state.handshake_messages.append(ske)
        cke = ClientKeyExchangeGenerator(
                cipher=constants.CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                p_1_as_share=True)

        ret = cke.generate(state)
        self.assertEqual(ret.dh_Yc, 20)

    def test_post_send(self):
        state = ConnectionState()
        state.get_server_public_key = lambda : self.priv_key
        cke = ClientKeyExchangeGenerator(
                constants.CipherSuite.TLS_RSA_WITH_NULL_MD5,
                (3, 3))

        ret = cke.generate(state)

        cke.post_send(state)

class TestChangeCipherSpecGenerator(unittest.TestCase):
    def test___init__(self):
        ccs = ChangeCipherSpecGenerator()

        self.assertIsNotNone(ccs)

    def test_generate(self):
        ccs = ChangeCipherSpecGenerator()
        ret = ccs.generate(None)

        self.assertIsInstance(ret, messages.ChangeCipherSpec)

    def test_post_send(self):
        ccsg = ChangeCipherSpecGenerator()
        ccsg.generate(None)
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        ccsg.post_send(state)

        self.assertTrue(state.msg_sock.calcPendingStates.called)
        self.assertTrue(state.msg_sock.changeWriteState.called)

    def test_post_send_with_extended_master_secret(self):
        ccsg = ChangeCipherSpecGenerator()
        ccsg.generate(None)
        state = ConnectionState()
        state.extended_master_secret = True
        state.msg_sock = mock.MagicMock()

        with mock.patch('tlsfuzzer.messages.calcExtendedMasterSecret') as mthd:
            mthd.return_value = bytearray(48)
            ccsg.post_send(state)
        mthd.assert_called_once_with(state.version, state.cipher,
                                     state.key['premaster_secret'],
                                     state.handshake_hashes)
        self.assertTrue(state.msg_sock.calcPendingStates.called)
        self.assertTrue(state.msg_sock.changeWriteState.called)

    def test_post_send_with_fake_true(self):
        ccsg = ChangeCipherSpecGenerator(fake=True)
        ccsg.generate(None)
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        with mock.patch('tlsfuzzer.messages.calcExtendedMasterSecret') as mthd:
            mthd.return_value = bytearray(48)
            ccsg.post_send(state)

        self.assertFalse(mthd.called)


class TestClientMasterKeyGenerator(unittest.TestCase):
    def test___init__(self):
        cmk = ClientMasterKeyGenerator()

    def test_generate_with_no_cipher(self):
        cmk = ClientMasterKeyGenerator()

        with self.assertRaises(NotImplementedError):
            cmk.generate(None)

    def test_generate(self):
        cmk = ClientMasterKeyGenerator(
                cipher=constants.CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5)
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.get_server_public_key = mock.MagicMock()

        ret = cmk.generate(state)
        self.assertEqual(ret.cipher,
                         constants.CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5)
        self.assertEqual(ret.clear_key, bytearray(0))
        self.assertEqual(ret.encrypted_key,
                         state.get_server_public_key().encrypt())
        self.assertEqual(ret.key_argument,
                         state.msg_sock.calcSSL2PendingStates())

    def test_generate_with_master_key(self):
        cmk = ClientMasterKeyGenerator(
                cipher=constants.CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
                master_key=bytearray(range(24)))
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.get_server_public_key = mock.MagicMock()

        ret = cmk.generate(state)

        state.msg_sock.calcSSL2PendingStates.assert_called_once_with(
                constants.CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
                bytearray(range(24)),
                bytearray(0),
                bytearray(0),
                None)

    def test_generate_with_export_cipher(self):
        cmk = ClientMasterKeyGenerator(
                cipher=constants.CipherSuite.SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5)
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.get_server_public_key = mock.MagicMock()

        ret = cmk.generate(state)

        self.assertEqual(len(ret.clear_key), 11)

    def test_generate_with_unknown_cipher(self):
        cmk = ClientMasterKeyGenerator(cipher=0xffffff)
        state = ConnectionState()

        with self.assertRaises(AssertionError):
            cmk.generate(state)

    def test_generate_with_des_cipher(self):
        cmk = ClientMasterKeyGenerator(
                cipher=constants.CipherSuite.SSL_CK_DES_64_CBC_WITH_MD5)
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.get_server_public_key = mock.MagicMock()

        ret = cmk.generate(state)

        self.assertEqual(ret.encrypted_key,
                         state.get_server_public_key().encrypt())

    def test_generate_with_session_key(self):
        cmk = ClientMasterKeyGenerator(
                cipher=constants.CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5)
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.get_server_public_key = mock.MagicMock()
        state.key['master_secret'] = bytearray(range(32))

        ret = cmk.generate(state)

        state.msg_sock.calcSSL2PendingStates.assert_called_once_with(
                constants.CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
                bytearray(range(32)),
                bytearray(0),
                bytearray(0),
                None)


class TestCertificateGenerator(unittest.TestCase):
    def test___init__(self):
        certg = CertificateGenerator()

        self.assertIsNotNone(certg)

    def test_generate(self):
        certg = CertificateGenerator()
        state = ConnectionState()

        msg = certg.generate(state)

        self.assertIsInstance(msg, messages.Certificate)
        self.assertIsNone(msg.cert_chain)
        self.assertEqual(msg.certificateType,
                         constants.CertificateType.x509)

    def test_generate_with_context(self):
        sig_algs = [constants.SignatureScheme.rsa_pss_rsae_sha512]
        cr = messages.CertificateRequest((3, 4)).create(
            sig_algs=sig_algs, context=b'zesty')
        ctx = []
        certg = CertificateGenerator(context=ctx)
        state = ConnectionState()
        state.version = (3, 3)

        state.handshake_messages.append(cr)
        ctx.append(cr)

        msg = certg.generate(state)

        self.assertIsInstance(msg, messages.Certificate)
        self.assertIsNone(msg.cert_chain)
        self.assertEqual(msg.certificateType,
                         constants.CertificateType.x509)
        self.assertEqual(msg.certificate_request_context, b'zesty')


class TestCertificateVerifyGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_key = generateRSAKey(1024)

    def test___init__(self):
        cert_ver_g = CertificateVerifyGenerator()

        self.assertIsNotNone(cert_ver_g)

    def test_generate_without_priv_key(self):
        cert_ver_g = CertificateVerifyGenerator()
        state = ConnectionState()

        with self.assertRaises(ValueError):
            cert_ver_g.generate(state)

    def test_generate_TLS_1_1(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 2)

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertTrue(priv_key.verify(
            msg.signature,
            secureHash(b'', 'md5') + secureHash(b'', 'sha1')))

    def test_generate_TLS_1_2(self):
        priv_key = generateRSAKey(2048)
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 256)
        # when no CR is present, select a secure algorithm by default
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_rsae_sha512)
        self.assertTrue(priv_key.verify(
            msg.signature,
            secureHash(b'', 'sha512'),
            padding="pss",
            hashAlg="sha512",
            saltLen=64))

    def test_generate_TLS_1_2_with_explicit_msg_sig_alg(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(
            priv_key,
            msg_alg=(constants.HashAlgorithm.sha1,
                     constants.SignatureAlgorithm.rsa))
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [(constants.HashAlgorithm.sha256,
              constants.SignatureAlgorithm.rsa),
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha1,
                          constants.SignatureAlgorithm.rsa))
        self.assertTrue(priv_key.verify(
            msg.signature,
            secureHash(req.write(), 'sha1'),
            hashAlg="sha1"))

    def test_generate_TLS_1_2_with_cert_request(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [(constants.HashAlgorithm.sha256,
              constants.SignatureAlgorithm.rsa),
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha256,
                          constants.SignatureAlgorithm.rsa))
        self.assertTrue(priv_key.verify(
            msg.signature,
            secureHash(req.write(), 'sha256'),
            hashAlg="sha256"))

    def test_generate_TLS_1_3(self):
        # RSA-PSS+SHA512 requires a 2048 bit key
        priv_key = keyfactory.generateRSAKey(2048)
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 4)

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 256)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_rsae_sha512)

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.rsa_pss_rsae_sha512,
                b'',
                b'',
                b'',
                # this is the PRF hash, not signature hash
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature, verif_bytes,
            "pss", "sha512", saltLen=64))

    def test_generate_TLS_1_3_with_cert_request(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 4)
        req = CertificateRequest((3, 4)).create([], [],
            [(constants.HashAlgorithm.md5, constants.SignatureAlgorithm.rsa),
             constants.SignatureScheme.rsa_pkcs1_sha1,
             constants.SignatureScheme.rsa_pkcs1_sha224,
             constants.SignatureScheme.rsa_pkcs1_sha256,
             constants.SignatureScheme.rsa_pkcs1_sha384,
             constants.SignatureScheme.rsa_pkcs1_sha512,
             constants.SignatureScheme.rsa_pss_rsae_sha256])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_rsae_sha256)

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.rsa_pss_rsae_sha256,
                b'',
                b'',
                b'',
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature, verif_bytes,
            "pss", "sha256", saltLen=32))

    def test_generate_TLS_1_3_in_PHA_(self):
        priv_key = self.priv_key
        ctx = []
        cert_ver_g = CertificateVerifyGenerator(priv_key, context=ctx)
        state = ConnectionState()
        state.version = (3, 4)
        req = CertificateRequest((3, 4)).create([], [],
            [(constants.HashAlgorithm.md5, constants.SignatureAlgorithm.rsa),
             constants.SignatureScheme.rsa_pkcs1_sha1,
             constants.SignatureScheme.rsa_pkcs1_sha224,
             constants.SignatureScheme.rsa_pkcs1_sha256,
             constants.SignatureScheme.rsa_pkcs1_sha384,
             constants.SignatureScheme.rsa_pkcs1_sha512,
             constants.SignatureScheme.rsa_pss_rsae_sha256],
            context=b'unique PHA context, totally random')
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())
        state.key['client finished handshake hashes'] = \
            HandshakeHashes()
        ctx.append(req)

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_rsae_sha256)

        hh = state.key['client finished handshake hashes'].copy()
        hh.update(ctx[0].write())

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                hh,
                constants.SignatureScheme.rsa_pss_rsae_sha256,
                b'',
                b'',
                b'',
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature, verif_bytes,
            "pss", "sha256", saltLen=32))

    def test_generate_with_mismatched_alg(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                sig_alg=(
                                                    constants.HashAlgorithm.md5,
                                                    constants.SignatureAlgorithm.rsa))
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [(constants.HashAlgorithm.sha256,
              constants.SignatureAlgorithm.rsa),
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha256,
                          constants.SignatureAlgorithm.rsa))

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, req.write(),
            "pkcs1", "sha256"))
        self.assertTrue(priv_key.hashAndVerify(
            msg.signature, req.write(),
            "pkcs1", "md5"))

    def test_generate_with_mismatched_CR_TLS1_2(self):
        priv_key = generateRSAKey(2048)
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [(constants.HashAlgorithm.sha256,
              constants.SignatureAlgorithm.ecdsa)])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 256)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_rsae_sha512)

        self.assertTrue(priv_key.hashAndVerify(
            msg.signature, req.write(),
            "pss", "sha512", 64))

    def test_generate_with_mismatched_CR_TLS1_3(self):
        priv_key = generateRSAKey(2048)
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 4)
        req = CertificateRequest((3, 4)).create([], [],
            [(constants.HashAlgorithm.sha256,
              constants.SignatureAlgorithm.ecdsa)])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 256)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_rsae_sha512)

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.rsa_pss_rsae_sha512,
                b'',
                b'',
                b'',
                # this is the PRF hash, not signature hash
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature, verif_bytes,
            "pss", "sha512", saltLen=64))

    def test_generate_with_mismatched_CR_RSA_PSS(self):
        priv_key = Python_RSAKey.generate(2048, "rsa-pss")
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [(constants.HashAlgorithm.sha256,
              constants.SignatureAlgorithm.ecdsa)])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 256)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_pss_sha512)

        self.assertTrue(priv_key.hashAndVerify(
            msg.signature, req.write(),
            "pss", "sha512", 64))

    def test_generate_with_rsa_pss_rsae_alg(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_sha256)

        self.assertTrue(priv_key.hashAndVerify(
            msg.signature, req.write(),
            "pss", "sha256", 32))

    def test_generate_with_no_key(self):
        cert_ver_g = CertificateVerifyGenerator(signature=bytearray(b'xxxx'))
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_rsae_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(msg.signature, bytearray(b'xxxx'))
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_rsae_sha256)

    def test_generate_with_rsa_pss_pss_alg(self):
        priv_key = Python_RSAKey.generate(1024, "rsa-pss")
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_rsae_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]
        state.handshake_hashes.update(req.write())

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_pss_sha256)

        self.assertTrue(priv_key.hashAndVerify(
            msg.signature, req.write(),
            "pss", "sha256", 32))

    def test_generate_with_rsa_with_subs(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_subs={4: 0x00})
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [(constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        dec_sig = numberToByteArray(priv_key._rawPublicKeyOp(
                                                bytesToNumber(msg.signature)),
                                    128)
        self.assertEqual(dec_sig[4], 0x00)
        # since we're siging the same set of messages always, the hash in
        # signature is also the same
        self.assertEqual(dec_sig[-1], 0x09)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pkcs1_sha1)

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, b'',
            "pkcs1", "sha1"))

    def test_generate_with_rsa_with_large_xors(self):
        # the xor can make the encrypted value too large (larger than the
        # modulus) verify that it doesn't break encryption (but the signature
        # will be completely invalid)
        priv_key = generateRSAKey(1020)
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_xors={0: 0x80})
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [(constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        dec_sig = numberToByteArray(priv_key._rawPublicKeyOp(
                                                bytesToNumber(msg.signature)),
                                    128)
        self.assertEqual(dec_sig[0] & 0x80, 0x00)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pkcs1_sha1)

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, b'',
            "pkcs1", "sha1"))

    def test_generate_with_rsa_with_xors(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_xors={4: 0xff})
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [(constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        dec_sig = numberToByteArray(priv_key._rawPublicKeyOp(
                                                bytesToNumber(msg.signature)),
                                    128)
        self.assertEqual(dec_sig[4], 0x00)
        # since we're siging the same set of messages always, the hash in
        # signature is also the same
        self.assertEqual(dec_sig[-1], 0x09)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pkcs1_sha1)

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, b'',
            "pkcs1", "sha1"))

    def test_generate_with_rsa_pss_with_subs(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_subs={2: 0xff,
                                                              -1: 0xff})
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        dec_sig = numberToByteArray(priv_key._rawPublicKeyOp(
                                                bytesToNumber(msg.signature)),
                                    128)
        self.assertEqual(dec_sig[2], 0xff)
        self.assertEqual(dec_sig[-1], 0xff)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_sha256)

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, b'',
            "pss", "sha256", 32))

    def test_generate_with_rsa_pss_with_xors(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_xors={-1: 0xff})
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        dec_sig = numberToByteArray(priv_key._rawPublicKeyOp(
                                                bytesToNumber(msg.signature)),
                                    128)
        self.assertEqual(dec_sig[-1], 0xbc ^ 0xff)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_sha256)

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, b'',
            "pss", "sha256", 32))

    def test_generate_with_tls1_0_version(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key, sig_version=(3, 1))
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_rsae_sha256,
             constants.SignatureScheme.rsa_pkcs1_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        # because we are creating a TLS 1.0 signature, we want to select
        # a signature algorithm that matches TLS 1.0 most closely
        # (the last 20 bytes of a decrypted signature will match)
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha1,
                          constants.SignatureAlgorithm.rsa))

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, b'',
            "pkcs1", "sha1"))
        self.assertTrue(priv_key.verify(
            msg.signature,
            secureHash(b"", "md5") + secureHash(b"", "sha1")))

    def test_generate_with_ssl3_0_version(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key, sig_version=(3, 0))
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_rsae_sha256,
             constants.SignatureScheme.rsa_pkcs1_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        # just like with TLS 1.0, we want to use one that uses
        # algorithms closest to the ones we will actually use in the signature
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha1,
                          constants.SignatureAlgorithm.rsa))

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, b'',
            "pkcs1", "sha1"))
        verify_bytes = KeyExchange.calcVerifyBytes(
                (3, 0),
                state.handshake_hashes,
                None,
                b'',
                b'',
                b'')
        self.assertTrue(priv_key.verify(
            msg.signature,
            verify_bytes))

    def test_generate_with_empty_signature(self):
        cert_ver_g = CertificateVerifyGenerator(signature=bytearray())
        state = ConnectionState()
        state.version = (3, 3)

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(msg.signature, bytearray())

    def test_generate_with_mismatched_mgf1(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key, sig_version=(3, 4),
                                                mgf1_hash="sha512")
        state = ConnectionState()
        state.version = (3, 4)
        req = CertificateRequest((3, 4)).create([], [],
            [constants.SignatureScheme.rsa_pss_rsae_sha256])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_rsae_sha256)

        verify_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.rsa_pss_rsae_sha256,
                b'',
                b'',
                b'',
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature,
            verify_bytes,
            "pss", "sha512", 32))

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, verify_bytes,
            "pss", "sha256", 32))

    def test_generate_with_mismatched_mgf1_and_salt_len(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key, sig_version=(3, 4),
                                                mgf1_hash="sha384",
                                                rsa_pss_salt_len=48)
        state = ConnectionState()
        state.version = (3, 4)
        req = CertificateRequest((3, 4)).create([], [],
            [constants.SignatureScheme.rsa_pss_rsae_sha256])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_rsae_sha256)

        verify_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.rsa_pss_rsae_sha256,
                b'',
                b'',
                b'',
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature,
            verify_bytes,
            "pss", "sha384", 48))

        self.assertFalse(priv_key.hashAndVerify(
            msg.signature, verify_bytes,
            "pss", "sha256", 32))

    def test_generate_with_key_and_certificate(self):
        priv_key = Python_RSAKey.generate(1024, "rsa-pss")
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        cert = Certificate(constants.CertificateType.x509, (3, 3))\
            .create(rsa_pss_cert)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_rsae_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha384])

        state.handshake_messages = [req, cert]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(len(msg.signature), 128)
        # when no CR is present, select a secure algorithm by default
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.rsa_pss_pss_sha256)

        self.assertTrue(priv_key.verify(
            msg.signature,
            secureHash(b"", "sha256"),
            "pss", "sha256", 32))


class TestCertificateVerifyGeneratorECDSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv_key = Python_ECDSAKey(None, None, "NIST256p", 12)

    def test_generate_with_ecdsa_and_no_cert_req_in_tls1_3(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 4)

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha256,
                          constants.SignatureAlgorithm.ecdsa))

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.ecdsa_secp256r1_sha256,
                b'',
                b'',
                b'',
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature, verif_bytes,
            "", "sha256"))

    def test_generate_with_ecdsa_cert_and_no_key_in_tls1_3(self):
        cert_ver_g = CertificateVerifyGenerator(signature=b"ABCDEF")
        state = ConnectionState()
        state.version = (3, 4)
        cert = messages.Certificate(constants.CertificateType.x509, (3, 4))\
            .create(ecdsa_cert)
        state.handshake_messages = [cert]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(msg.signature, bytearray(b'ABCDEF'))
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha256,
                          constants.SignatureAlgorithm.ecdsa))

    def test_generate_with_ecdsa_cert_and_no_key_in_tls1_2(self):
        cert_ver_g = CertificateVerifyGenerator(signature=b"ABCDEF")
        state = ConnectionState()
        state.version = (3, 3)
        cert = messages.Certificate(constants.CertificateType.x509, (3, 3))\
            .create(ecdsa_cert)
        state.handshake_messages = [cert]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(msg.signature, bytearray(b'ABCDEF'))
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha512,
                          constants.SignatureAlgorithm.ecdsa))

    def test_generate_with_ecdsa_cert_and_no_key_unmatched_CR_in_tls1_2(self):
        cert_ver_g = CertificateVerifyGenerator(signature=b"ABCDEF")
        state = ConnectionState()
        state.version = (3, 3)
        cert = messages.Certificate(constants.CertificateType.x509, (3, 3))\
            .create(ecdsa_cert)
        cert_req = messages.CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_pss_sha256])
        state.handshake_messages = [cert_req, cert]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertEqual(msg.signature, bytearray(b'ABCDEF'))
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha512,
                          constants.SignatureAlgorithm.ecdsa))

    def test_generate_with_ecdsa_in_TLS1_0(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 1)
        req = CertificateRequest((3, 1)).create()
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        # the SignatureScheme.ecdsa_secp*_sha* ignore the curve type in
        # TLS 1.2, so the negotiation will always select SHA512 algorithm
        self.assertEqual(msg.signatureAlgorithm, None)

        self.assertTrue(priv_key.verify(
            msg.signature, secureHash(b"", "sha1"),
            "", "sha1"))

    def test_generate_with_ecdsa_with_TLS1_0_format(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key, sig_version=(3, 1))
        state = ConnectionState()
        state.version = (3, 3)
        req = messages.CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.ecdsa_secp256r1_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.ecdsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        # the SignatureScheme.ecdsa_secp*_sha* ignore the curve type in
        # TLS 1.2, so the negotiation will always select SHA512 algorithm
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha1,
                          constants.SignatureAlgorithm.ecdsa))

        self.assertTrue(priv_key.verify(
            msg.signature, secureHash(b"", "sha1"),
            "", "sha1"))

    def test_generate_with_ecdsa_256_alg(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.ecdsa_secp521r1_sha512,
             constants.SignatureScheme.ecdsa_secp384r1_sha384,
             constants.SignatureScheme.ecdsa_secp256r1_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        # the SignatureScheme.ecdsa_secp*_sha* ignore the curve type in
        # TLS 1.2, so the negotiation will always select SHA512 algorithm
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha512,
                          constants.SignatureAlgorithm.ecdsa))

        self.assertTrue(priv_key.verify(
            msg.signature, secureHash(b"", "sha512")[:32],
            "", "sha512"))

    def test_generate_with_ecdsa_256_alg_and_non_matching_CR_tls1_3(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 4)
        req = CertificateRequest((3, 4)).create([], [],
            [constants.SignatureScheme.rsa_pss_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha256,
                          constants.SignatureAlgorithm.ecdsa))

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.ecdsa_secp256r1_sha256,
                b'',
                b'',
                b'',
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature, verif_bytes,
            "", "sha256"))

    def test_generate_with_ecdsa_256_alg_and_non_matching_CR_tls1_2(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.rsa_pss_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha512,
                          constants.SignatureAlgorithm.ecdsa))

        self.assertTrue(priv_key.verify(
            msg.signature, secureHash(b"", "sha512")[:32],
            "", "sha512"))

    def test_generate_with_ecdsa_384_alg(self):
        priv_key = Python_ECDSAKey(None, None, "NIST384p", 11)
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.ecdsa_secp521r1_sha512,
             constants.SignatureScheme.ecdsa_secp384r1_sha384,
             constants.SignatureScheme.ecdsa_secp256r1_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        # the SignatureScheme.ecdsa_secp*_sha* ignore the curve type in
        # TLS 1.2, so the negotiation will always select SHA512 algorithm
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha512,
                          constants.SignatureAlgorithm.ecdsa))

        self.assertTrue(priv_key.verify(
            msg.signature, secureHash(b"", "sha512")[:48],
            "", "sha512"))

    def test_generate_with_ecdsa_521_alg(self):
        priv_key = Python_ECDSAKey(None, None, "NIST521p", 10)
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.ecdsa_secp521r1_sha512,
             constants.SignatureScheme.ecdsa_secp384r1_sha384,
             constants.SignatureScheme.ecdsa_secp256r1_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        # the SignatureScheme.ecdsa_secp*_sha* ignore the curve type in
        # TLS 1.2, so the negotiation will always select SHA512 algorithm
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha512,
                          constants.SignatureAlgorithm.ecdsa))

        self.assertTrue(priv_key.verify(
            msg.signature, secureHash(b"", "sha512"),
            "", "sha512"))

    def test_generate_with_ecdsa_256_alg_in_tls1_3(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 4)
        req = CertificateRequest((3, 4)).create([], [],
            [constants.SignatureScheme.ecdsa_secp521r1_sha512,
             constants.SignatureScheme.ecdsa_secp384r1_sha384,
             constants.SignatureScheme.ecdsa_secp256r1_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.ecdsa_secp256r1_sha256)

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.ecdsa_secp256r1_sha256,
                b'',
                b'',
                b'',
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature, verif_bytes,
            "", "sha256"))

    def test_generate_with_ecdsa_384_alg(self):
        priv_key = Python_ECDSAKey(None, None, "NIST384p", 11)
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 4)
        req = CertificateRequest((3, 4)).create([], [],
            [constants.SignatureScheme.ecdsa_secp521r1_sha512,
             constants.SignatureScheme.ecdsa_secp384r1_sha384,
             constants.SignatureScheme.ecdsa_secp256r1_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.ecdsa_secp384r1_sha384)

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.ecdsa_secp384r1_sha384,
                b'',
                b'',
                b'',
                # PRF, not hash of signature
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature, verif_bytes,
            "", "sha384"))

    def test_generate_with_ecdsa_521_alg(self):
        priv_key = Python_ECDSAKey(None, None, "NIST521p", 10)
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 4)
        req = CertificateRequest((3, 4)).create([], [],
            [constants.SignatureScheme.ecdsa_secp521r1_sha512,
             constants.SignatureScheme.ecdsa_secp384r1_sha384,
             constants.SignatureScheme.ecdsa_secp256r1_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.ecdsa_secp521r1_sha512)

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.ecdsa_secp521r1_sha512,
                b'',
                b'',
                b'',
                # PRF, not hash of signature
                "sha256")

        self.assertTrue(priv_key.verify(
            msg.signature, verif_bytes,
            "", "sha512"))

    def test_generate_with_xors(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_xors={0: 0xff})
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.ecdsa_secp521r1_sha512,
             constants.SignatureScheme.ecdsa_secp384r1_sha384,
             constants.SignatureScheme.ecdsa_secp256r1_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        # the SignatureScheme.ecdsa_secp*_sha* ignore the curve type in
        # TLS 1.2, so the negotiation will always select SHA512 algorithm
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha512,
                          constants.SignatureAlgorithm.ecdsa))
        self.assertEqual(msg.signature[0] ^ 0xff, 0x30)

        sig = msg.signature
        self.assertFalse(priv_key.verify(
            sig, secureHash(b"", "sha512")[:32],
            "", "sha512"))

        sig[0] ^= 0xff
        self.assertTrue(priv_key.verify(
            sig, secureHash(b"", "sha512")[:32],
            "", "sha512"))

    def test_generate_with_xors_in_tls1_0(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_xors={0: 0xff})
        state = ConnectionState()
        state.version = (3, 1)
        req = CertificateRequest((3, 1)).create()
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        self.assertIsNone(msg.signatureAlgorithm)
        self.assertEqual(msg.signature[0] ^ 0xff, 0x30)

        sig = msg.signature
        self.assertFalse(priv_key.verify(
            sig, secureHash(b"", "sha1"),
            "", "sha1"))

        sig[0] ^= 0xff
        self.assertTrue(priv_key.verify(
            sig, secureHash(b"", "sha1"),
            "", "sha1"))

    def test_generate_with_subs(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_subs={0: 0xff})
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.ecdsa_secp521r1_sha512,
             constants.SignatureScheme.ecdsa_secp384r1_sha384,
             constants.SignatureScheme.ecdsa_secp256r1_sha256,
             constants.SignatureScheme.rsa_pss_pss_sha256,
             (constants.HashAlgorithm.sha1,
              constants.SignatureAlgorithm.rsa)])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        # the SignatureScheme.ecdsa_secp*_sha* ignore the curve type in
        # TLS 1.2, so the negotiation will always select SHA512 algorithm
        self.assertEqual(msg.signatureAlgorithm,
                         (constants.HashAlgorithm.sha512,
                          constants.SignatureAlgorithm.ecdsa))
        self.assertEqual(msg.signature[0], 0xff)

        sig = msg.signature
        self.assertFalse(priv_key.verify(
            sig, secureHash(b"", "sha512")[:32],
            "", "sha512"))

        sig[0] = 0x30
        self.assertTrue(priv_key.verify(
            sig, secureHash(b"", "sha512")[:32],
            "", "sha512"))

    def test_generate_with_subs_in_TLS1_0(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_subs={0: 0xff})
        state = ConnectionState()
        state.version = (3, 1)
        req = CertificateRequest((3, 1)).create()
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        # the SignatureScheme.ecdsa_secp*_sha* ignore the curve type in
        # TLS 1.2, so the negotiation will always select SHA512 algorithm
        self.assertEqual(msg.signatureAlgorithm, None)

        sig = msg.signature
        self.assertFalse(priv_key.verify(
            sig, secureHash(b"", "sha1"),
            "", "sha1"))

        sig[0] = 0x30
        self.assertTrue(priv_key.verify(
            sig, secureHash(b"", "sha1"),
            "", "sha1"))

class TestCertificateVerifyGeneratorEdDSA(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p_key = SigningKey.generate(Ed25519)
        cls.priv_key = Python_EdDSAKey(None, p_key)

    def test_generate_with_eddsa_and_no_cert_req_in_tls1_3(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key)
        state = ConnectionState()
        state.version = (3, 4)

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.ed25519)

        verif_bytes = KeyExchange.calcVerifyBytes(
                (3, 4),
                state.handshake_hashes,
                constants.SignatureScheme.ed25519,
                b'',
                b'',
                b'',
                "sha256")

        self.assertTrue(priv_key.hashAndVerify(
            msg.signature, verif_bytes,
            "", "sha256"))

    def test_generate_with_xors(self):
        priv_key = self.priv_key
        cert_ver_g = CertificateVerifyGenerator(priv_key,
                                                padding_xors={0: 0xff})
        state = ConnectionState()
        state.version = (3, 3)
        req = CertificateRequest((3, 3)).create([], [],
            [constants.SignatureScheme.ed25519])
        state.handshake_messages = [req]

        msg = cert_ver_g.generate(state)

        self.assertIsNotNone(msg)
        self.assertTrue(msg.signature)
        self.assertEqual(msg.signatureAlgorithm,
                         constants.SignatureScheme.ed25519)

        sig = msg.signature
        self.assertFalse(priv_key.hashAndVerify(
            sig, b""))

        sig[0] ^= 0xff
        self.assertTrue(priv_key.hashAndVerify(
            sig, b""))


class TestClearContext(unittest.TestCase):
    def test___init__(self):
        ctx = []
        cc = ClearContext(ctx)

        self.assertIs(cc.context, ctx)
        self.assertTrue(cc.is_command())
        self.assertFalse(cc.is_expect())
        self.assertFalse(cc.is_generator())

    def test_process(self):
        ctx = ["abc", 123]
        cc = ClearContext(ctx)
        self.assertEqual(ctx, ["abc", 123])

        cc.process(None)

        self.assertEqual(ctx, [])


class TestAlertGenerator(unittest.TestCase):
    def test_default_settings(self):
        a = AlertGenerator()

        self.assertIsNotNone(a)

        state = ConnectionState()

        ret = a.generate(state)
        self.assertEqual(ret.level, constants.AlertLevel.warning)
        self.assertEqual(ret.description,
                         constants.AlertDescription.close_notify)

    def test___init___with_parameters(self):
        a = AlertGenerator(constants.AlertLevel.fatal,
                           constants.AlertDescription.decode_error)
        self.assertIsNotNone(a)

        state = ConnectionState()

        ret = a.generate(state)
        self.assertEqual(ret.level, constants.AlertLevel.fatal)
        self.assertEqual(ret.description,
                         constants.AlertDescription.decode_error)


class TestFinishedGenerator(unittest.TestCase):
    def test___init__(self):
        fg = FinishedGenerator()

        self.assertIsNotNone(fg)

    def test_generate(self):
        fg = FinishedGenerator()
        state = ConnectionState()

        ret = fg.generate(state)

        self.assertIsInstance(ret, messages.Finished)

    def test_post_send(self):
        fg = FinishedGenerator()
        state = ConnectionState()

        ret = fg.generate(state)

        self.assertNotIn(ret, state.handshake_messages)

        fg.post_send(state)

        self.assertIn(ret, state.handshake_messages)

    def test_post_send_with_resumption(self):
        fg = FinishedGenerator()
        state = ConnectionState()
        state.resuming = True

        ret = fg.generate(state)
        fg.post_send(state)

        self.assertFalse(state.resuming)

    def test_generate_with_ssl2(self):
        fg = FinishedGenerator((0, 2))
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.session_id = bytearray(b'abba')

        ret = fg.generate(state)

        self.assertEqual(ret.verify_data, bytearray(b'abba'))
        state.msg_sock.changeWriteState.assert_called_once_with()
        state.msg_sock.changeReadState.assert_called_once_with()

    def test_generate_in_tls13(self):
        fg = FinishedGenerator((3, 4))

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.cipher = constants.CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)
        state.key['client handshake traffic secret'] = bytearray(32)

        ret = fg.generate(state)

        self.assertEqual(ret.verify_data, bytearray(
            b'\x14\xa5e\xa67\xfe\xa3(\xd3\xac\x95\xecX\xb7\xc0\xd4u\xef'
            b'\xb3V\x8f\xc7[\xcdD\xc8\xa4\x86\xcf\xd3\xc9\x0c'))

        state.key['handshake secret'] = bytearray(32)
        state.key['master secret'] = bytearray(32)

        fg.post_send(state)

        state.msg_sock.changeWriteState.assert_called_once_with()

        self.assertEqual(state.key['resumption master secret'],
            bytearray(b'\x89\xd8\x00l c$\x01\x0f\xd9j\x16\xa3\xbaV\xfesT\x8b'
                      b'\xc6\xeb\x0f~\r\xbd\xb3R\xeb\xd5\x08\xa7\xbd'))

    def test_generate_in_tls13_with_pha(self):
        ctx = []

        fg = FinishedGenerator((3, 4), context=ctx)

        cv = messages.CertificateVerify((3, 4)).create(
            b'abcdef', constants.SignatureScheme.rsa_pss_rsae_sha256)
        ctx.append(cv)

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.cipher = constants.CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)
        state.key['client handshake traffic secret'] = bytearray(32)
        state.key['client application traffic secret'] = bytearray(b'x'*32)
        state.key['client finished handshake hashes'] = HandshakeHashes()

        ret = fg.generate(state)

        print(repr(ret.verify_data))
        self.assertEqual(ret.verify_data,
            bytearray(b'q\xf1l\x05\x94\xb8"\xb2L7\xce\xd5\xb3\x00\xa6\r\x17*'
                      b'\xcc\xe7\xdc\xa6\xf0c\xd7\x90I\x11}\xbfq:'))
        state.key['handshake secret'] = bytearray(32)
        state.key['master secret'] = bytearray(32)

        fg.post_send(state)

        self.assertTrue(not state.msg_sock.changeWriteState.called)

        self.assertNotIn('resumption master secret', state.key)

    def test_generate_in_tls13_with_truncation(self):
        fg = FinishedGenerator((3, 4), trunc_start=2, trunc_end=-2)

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.cipher = constants.CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)
        state.key['client handshake traffic secret'] = bytearray(32)

        ret = fg.generate(state)

        self.assertEqual(ret.verify_data, bytearray(
            b'e\xa67\xfe\xa3(\xd3\xac\x95\xecX\xb7\xc0\xd4u\xef'
            b'\xb3V\x8f\xc7[\xcdD\xc8\xa4\x86\xcf\xd3'))

    def test_generate_in_tls13_with_padding(self):
        fg = FinishedGenerator((3, 4), pad_byte=0, pad_left=1, pad_right=1)

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.cipher = constants.CipherSuite.TLS_AES_128_GCM_SHA256
        state.version = (3, 4)
        state.key['client handshake traffic secret'] = bytearray(32)

        ret = fg.generate(state)

        self.assertEqual(ret.verify_data, bytearray(
            b'\x00\x14\xa5e\xa67\xfe\xa3(\xd3\xac\x95\xecX\xb7\xc0\xd4u\xef'
            b'\xb3V\x8f\xc7[\xcdD\xc8\xa4\x86\xcf\xd3\xc9\x0c\x00'))


class TestKeyUpdateGenerator(unittest.TestCase):

    def test_default_settings(self):
        ku = KeyUpdateGenerator()

        self.assertIsNotNone(ku)

        state = ConnectionState()

        ret = ku.generate(state)
        self.assertEqual(ret.message_type,
                         constants.KeyUpdateMessageType.update_not_requested)

    def test___init___with_parameters(self):
        ku = KeyUpdateGenerator(
            constants.KeyUpdateMessageType.update_requested)

        self.assertIsNotNone(ku)

        state = ConnectionState()

        ret = ku.generate(state)
        self.assertEqual(ret.message_type,
                         constants.KeyUpdateMessageType.update_requested)

    def test_post_send(self):
        ku = KeyUpdateGenerator()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.cipher = constants.CipherSuite.TLS_AES_128_GCM_SHA256
        client_app_secret = mock.Mock()
        server_app_secret = mock.Mock()
        state.key['client application traffic secret'] = client_app_secret
        state.key['server application traffic secret'] = server_app_secret
        state.msg_sock.calcTLS1_3KeyUpdate_reciever.return_value = (
            bytearray(32), bytearray(32))

        ku.post_send(state)
        state.msg_sock.calcTLS1_3KeyUpdate_reciever.assert_called_once_with(
                state.cipher, client_app_secret, server_app_secret)


class TestResetHandshakeHashes(unittest.TestCase):
    def test___init__(self):
        node = ResetHandshakeHashes()

        self.assertIsNotNone(node)

    def test_process(self):
        node = ResetHandshakeHashes()

        state = ConnectionState()
        hashes = state.handshake_hashes

        self.assertIs(hashes, state.handshake_hashes)

        node.process(state)

        self.assertIsNot(hashes, state.handshake_hashes)

class TestResetRenegotiationInfo(unittest.TestCase):
    def test___init__(self):
        node = ResetRenegotiationInfo()

        self.assertIsNotNone(node)

    def test_process(self):
        node = ResetRenegotiationInfo()

        state = ConnectionState()
        state.key['client_verify_data'] = bytearray(b'\xde\xad\xc0\xde')
        state.key['server_verify_data'] = bytearray(b'\xc0\xff\xee')

        node.process(state)

        self.assertEqual(state.key['client_verify_data'], bytearray(0))
        self.assertEqual(state.key['server_verify_data'], bytearray(0))

class TestSetMaxRecordSize(unittest.TestCase):
    def test___init__(self):
        node = SetMaxRecordSize()
        self.assertIsNotNone(node)

    def test_process(self):
        node = SetMaxRecordSize()

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()
        state.msg_sock.recordSize = 1024

        node.process(state)

        self.assertEqual(2**14, state.msg_sock.recordSize)

    def test_process_with_size(self):
        node = SetMaxRecordSize(2048)

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        node.process(state)

        self.assertEqual(2048, state.msg_sock.recordSize)


class TestSetPaddingCallback(unittest.TestCase):
    def test___init__(self):
        node = SetPaddingCallback()
        self.assertIsNotNone(node)

    def test_process_fixed_len_padding(self):
        node = SetPaddingCallback(SetPaddingCallback.fixed_length_cb(42))

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        node.process(state)

        self.assertEqual(42, state.msg_sock.padding_cb(13,
                         constants.ContentType.application_data,
                         2**14 - 1))

    def test_process_fill_padding(self):
        node = SetPaddingCallback(SetPaddingCallback.fill_padding_cb)

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        node.process(state)

        self.assertEqual(2**14 - 13 - 1,
                         state.msg_sock.padding_cb(13,
                         constants.ContentType.application_data,
                         2**14 - 1))

    def test_process_custom_callback(self):

        def _my_cb(length, contenttype, max_padding):
            return 1337

        node = SetPaddingCallback(_my_cb)
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        node.process(state)

        self.assertEqual(1337, state.msg_sock.padding_cb(13,
                         constants.ContentType.application_data,
                         2**14 - 1))

    def test_unset_padding_callback(self):
        node = SetPaddingCallback(SetPaddingCallback.fixed_length_cb(16))
        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        node.process(state)

        self.assertEqual(16, state.msg_sock.padding_cb(13,
                         constants.ContentType.application_data,
                         2**14 - 1))

        unset_node = SetPaddingCallback()
        unset_node.process(state)

        self.assertIsNone(state.msg_sock.padding_cb)

    def test_with_padding_larger_than_possible(self):
        node = SetPaddingCallback(SetPaddingCallback.fixed_length_cb(42))

        state = ConnectionState()
        state.msg_sock = mock.MagicMock()

        node.process(state)

        with self.assertRaises(ValueError):
            state.msg_sock.padding_cb(20,
                                      constants.ContentType.application_data,
                                      32)


class TestRenegotiationInfoExtension(unittest.TestCase):
    def test___init__(self):
        ext = RenegotiationInfoExtension()
        self.assertIsNotNone(ext)

    def test_write(self):
        ext = RenegotiationInfoExtension()

        self.assertEqual(ext.write(), bytearray(
            b'\xff\x01' +       # extension type
            b'\x00\x00'         # overall extension length
            ))

    def test_write_with_data(self):
        ext = RenegotiationInfoExtension()
        ext.create(bytearray(b'\xab\xcd'))

        self.assertEqual(ext.write(), bytearray(
            b'\xff\x01' +       # extension type
            b'\x00\x03' +       # overall extension length
            b'\x02' +           # payload length
            b'\xab\xcd'         # payload
            ))

    def test_parse(self):
        parser = Parser(bytearray(b'\x02\xab\xcd'))

        ext = RenegotiationInfoExtension()
        ext.parse(parser)

        self.assertEqual(bytearray(b'\xab\xcd'), ext.renegotiated_connection)

class TestHandshakePadding(unittest.TestCase):
    def setUp(self):
        self.state = ConnectionState()
        self.hello_gen = ClientHelloGenerator()

        self.vanilla_hello = self.hello_gen.generate(self.state).write()

    def test_no_option(self):
        self.assertEqual(len(self.vanilla_hello), 43)

        hello_gen = pad_handshake(ClientHelloGenerator())

        unmodified_hello = hello_gen.generate(self.state).write()
        self.assertEqual(len(unmodified_hello), 43)

        self.assertEqual(self.vanilla_hello, unmodified_hello)

    def test_add_padding(self):
        hello_gen = pad_handshake(ClientHelloGenerator(), 1)

        padded_hello = hello_gen.generate(self.state).write()

        self.assertEqual(len(padded_hello), 44)

        # skip the first 4 bytes as they have different length
        self.assertEqual(self.vanilla_hello[4:] + bytearray(1),
                         padded_hello[4:])

    def test_add_specific_padding(self):
        hello_gen = pad_handshake(ClientHelloGenerator(), 2, 0xab)

        padded_hello = hello_gen.generate(self.state).write()

        self.assertEqual(len(padded_hello), 45)

        # skip the first 4 bytes as they have different length
        self.assertEqual(self.vanilla_hello[4:] + bytearray(b'\xab\xab'),
                         padded_hello[4:])

    def test_pad_with_data(self):
        pad = bytearray(b'\xff\x01\x00\x01\x00')
        hello_gen = pad_handshake(ClientHelloGenerator(),
                                  pad=pad)

        padded_hello = hello_gen.generate(self.state).write()

        self.assertEqual(len(padded_hello), len(self.vanilla_hello) + len(pad))

        self.assertEqual(self.vanilla_hello[4:] + pad,
                         padded_hello[4:])
        self.assertNotEqual(self.vanilla_hello[:4],
                            padded_hello[:4])

    def test_truncate(self):
        hello_gen = truncate_handshake(ClientHelloGenerator(), 1)

        padded_hello = hello_gen.generate(self.state).write()

        self.assertEqual(len(padded_hello), 42)

        # skip the first 4 bytes as they have different length
        self.assertEqual(self.vanilla_hello[4:-1],
                         padded_hello[4:])

class TestFuzzMessage(unittest.TestCase):
    def setUp(self):
        self.state = ConnectionState()
        self.hello_gen = ClientHelloGenerator()

        self.vanilla_hello = self.hello_gen.generate(self.state).write()

    def test_no_options(self):
        self.assertEqual(len(self.vanilla_hello), 43)

        hello_gen = fuzz_message(ClientHelloGenerator())

        unmodified_hello = hello_gen.generate(self.state).write()
        self.assertEqual(len(unmodified_hello), 43)

        self.assertEqual(self.vanilla_hello, unmodified_hello)

    def test_substitutions(self):
        hello_gen = fuzz_message(ClientHelloGenerator(), substitutions={4:0xff})
        modified_hello = hello_gen.generate(self.state).write()

        self.assertNotEqual(self.vanilla_hello, modified_hello)

        self.vanilla_hello[4] = 0xff

        self.assertEqual(self.vanilla_hello, modified_hello)

    def test_xors(self):
        hello_gen = fuzz_message(ClientHelloGenerator(), xors={4:0xff})
        modified_hello = hello_gen.generate(self.state).write()

        self.assertNotEqual(self.vanilla_hello, modified_hello)

        self.vanilla_hello[4] ^= 0xff

        self.assertEqual(self.vanilla_hello, modified_hello)

class TestFuzzMAC(unittest.TestCase):
    def setUp(self):
        self.state = ConnectionState()

        self.socket = MockSocket(bytearray())

        defragger = defragmenter.Defragmenter()
        defragger.add_static_size(constants.ContentType.alert, 2)
        defragger.add_static_size(constants.ContentType.change_cipher_spec, 1)
        defragger.add_dynamic_size(constants.ContentType.handshake, 1, 3)
        self.state.msg_sock = messagesocket.MessageSocket(self.socket,
                                                          defragger)

        self.state.msg_sock.version = (3, 3)
        self.state.msg_sock.calcPendingStates(constants.CipherSuite.\
                                                    TLS_RSA_WITH_NULL_MD5,
                                              bytearray(48),
                                              bytearray(32),
                                              bytearray(32),
                                              None)
        self.state.msg_sock.changeWriteState()

        self.expected_value = bytearray(
            b"\x16"         # content type
            b"\x03\x03"     # record layer protocol version
            b"\x00\x3b"     # record layer record length
            b"\x01"         # handshake message type
            b"\x00\x00\x27" # handshke protocol message length
            b"\x03\x03"     # client hello protocol version
            # random
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00"         # length of session_id
            b"\x00\x00"     # cipher_suites length
            b"\x01\x00"     # compression_methods (0 - uncompressed)
            # 128 bit MD5 HMAC value
            b"\x1cK \xce\xb3\x1d\x94\x0b\x0f\x9a\'\x9c\x87\x1a-`"
            )

        self.second_write = bytearray(self.expected_value[:-16])
        self.second_write += bytearray(
                # MD5 HMAC with sequence number of "2"
                b"\x84\xcb\\\xf2A\x0c\xd3<u\xf3\xce\x8dk\xa0\xd8/")

    def test_no_options(self):
        hello_gen = fuzz_mac(ClientHelloGenerator())

        unmodified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(unmodified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(unmodified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(self.socket.sent[0], self.expected_value)

    def test_xor_last_byte(self):
        hello_gen = fuzz_mac(ClientHelloGenerator(), xors={-1:0xff})

        modified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(modified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(modified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        self.expected_value[-1] ^= 0xff
        self.assertEqual(self.socket.sent[0], self.expected_value)

    def test_xor_first_byte(self):
        hello_gen = fuzz_mac(ClientHelloGenerator(), xors={0:0xff})

        modified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(modified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(modified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        # MD5 is 16 bytes long
        self.expected_value[-16] ^= 0xff
        self.assertEqual(self.socket.sent[0], self.expected_value)

    def test_substitute_last_byte(self):
        hello_gen = fuzz_mac(ClientHelloGenerator(), substitutions={0:0xff})

        modified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(modified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(modified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        # MD5 is 16 bytes long
        self.expected_value[-16] = 0xff
        self.assertEqual(self.socket.sent[0], self.expected_value)

    def test_post_send_no_options(self):
        hello_gen = fuzz_mac(ClientHelloGenerator())

        unmodified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(unmodified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(unmodified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(self.socket.sent[0], self.expected_value)

        hello_gen.post_send(self.state)

        self.state.msg_sock.sendMessageBlocking(unmodified_hello)

        self.assertEqual(len(self.socket.sent), 2)
        self.assertEqual(self.socket.sent[1], self.second_write)

    def test_post_send_xor_last_byte(self):
        hello_gen = fuzz_mac(ClientHelloGenerator(), xors={-1:0xff})

        modified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(modified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(modified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        self.expected_value[-1] ^= 0xff
        self.assertEqual(self.socket.sent[0], self.expected_value)

        hello_gen.post_send(self.state)

        self.state.msg_sock.sendMessageBlocking(modified_hello)

        self.assertEqual(len(self.socket.sent), 2)
        self.assertEqual(self.socket.sent[1], self.second_write)

class TestFuzzEncryptedMessage(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(os,
                                    'urandom',
                                    lambda x: bytearray(x))
        mock_random = patcher.start()

        self.addCleanup(patcher.stop)
        self.state = ConnectionState()

        self.socket = MockSocket(bytearray())

        defragger = defragmenter.Defragmenter()
        defragger.add_static_size(constants.ContentType.alert, 2)
        defragger.add_static_size(constants.ContentType.change_cipher_spec, 1)
        defragger.add_dynamic_size(constants.ContentType.handshake, 1, 3)
        self.state.msg_sock = messagesocket.MessageSocket(self.socket,
                                                          defragger)

        self.state.msg_sock.version = (3, 1)
        self.state.msg_sock.encryptThenMAC = True
        self.state.msg_sock.calcPendingStates(
                constants.CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                bytearray(48), # master secret
                bytearray(32), # client random
                bytearray(32), # server random
                None)

        self.state.msg_sock.changeWriteState()
        self.expected_value = bytearray(
            b'\x17' +           # application data
            b'\x03\x01' +       # TLS version
            b'\x00\x24' +       # length - 1 block + 20 bytes of MAC
            b'\xc7\xd6\xaf:.MY\x80W\x81\xd2|5A#\xd5' +
            b'X\xcd\xdc\'o\xb3I\xdd-\xfc\tneq~\x0f' +
            b'd\xdb\xbdw'
            )

    def test_no_changes(self):
        node = ApplicationDataGenerator(bytearray(b'test'))
        node = fuzz_encrypted_message(node)
        msg = node.generate(self.state)
        self.state.msg_sock.sendMessageBlocking(msg)
        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(self.socket.sent[0], self.expected_value)

    def test_xor_last_byte(self):
        node = ApplicationDataGenerator(bytearray(b'test'))
        node = fuzz_encrypted_message(node, xors={-1:0xff})
        msg = node.generate(self.state)
        self.state.msg_sock.sendMessageBlocking(msg)
        self.expected_value[-1] ^= 0xff
        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(self.socket.sent[0], self.expected_value)


class TestFuzzPadding(unittest.TestCase):
    def setUp(self):
        self.state = ConnectionState()
        self.socket = MockSocket(bytearray())

        defragger = defragmenter.Defragmenter()
        defragger.add_static_size(constants.ContentType.alert, 2)
        defragger.add_static_size(constants.ContentType.change_cipher_spec, 1)
        defragger.add_dynamic_size(constants.ContentType.handshake, 1, 3)
        self.state.msg_sock = messagesocket.MessageSocket(self.socket,
                                                          defragger)
        self.state.msg_sock.version = (3, 0)
        self.state.msg_sock.calcPendingStates(constants.CipherSuite.\
                                                TLS_RSA_WITH_AES_128_CBC_SHA,
                                              bytearray(48),
                                              bytearray(32),
                                              bytearray(32),
                                              None)
        self.state.msg_sock.changeWriteState()

    def test_no_options(self):
        hello_gen = fuzz_padding(ClientHelloGenerator())

        unmodified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(unmodified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(unmodified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(len(self.socket.sent[0]),
                         1 +        # record layer type
                         2 +        # protocol version
                         2 +        # record payload length field
                         43 +       # length of ClientHello
                         160 // 8 + # length of HMAC
                         1)         # size of length tag of padding (0)

    def test_min_length(self):
        hello_gen = fuzz_padding(ClientHelloGenerator(),
                                 min_length=0)

        unmodified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(unmodified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(unmodified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(len(self.socket.sent[0]),
                         1 +        # record layer type
                         2 +        # protocol version
                         2 +        # record payload length field
                         43 +       # length of ClientHello
                         160 // 8 + # length of HMAC
                         1)         # size of length tag of padding (0)

    def test_min_length_with_high_value(self):
        hello_gen = fuzz_padding(ClientHelloGenerator(),
                                 min_length=200)

        unmodified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(unmodified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(unmodified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(len(self.socket.sent[0]),
                         1 +        # record layer type
                         2 +        # protocol version
                         2 +        # record payload length field
                         43 +       # length of ClientHello
                         160 // 8 + # length of HMAC
                         1 +        # size of length tag of padding (0)
                         208)       # minimal length of padding

    def test_min_length_with_post_send(self):
        hello_gen = fuzz_padding(ClientHelloGenerator(),
                                 min_length=200)

        unmodified_hello = hello_gen.generate(self.state)
        self.assertEqual(len(unmodified_hello.write()), 43)

        self.state.msg_sock.sendMessageBlocking(unmodified_hello)

        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(len(self.socket.sent[0]),
                         1 +        # record layer type
                         2 +        # protocol version
                         2 +        # record payload length field
                         43 +       # length of ClientHello
                         160 // 8 + # length of HMAC
                         1 +        # size of length tag of padding (0)
                         208)       # minimal length of padding greater than 200

        hello_gen.post_send(self.state)

        clean_hello_gen = ClientHelloGenerator()
        clean_hello = clean_hello_gen.generate(self.state)
        self.state.msg_sock.sendMessageBlocking(clean_hello)

        self.assertEqual(len(self.socket.sent), 2)
        self.assertEqual(len(self.socket.sent[1]),
                         1 +        # record layer type
                         2 +        # protocol version
                         2 +        # record payload length field
                         43 +       # length of ClientHello
                         160 // 8 + # length of HMAC
                         1 +        # size of length tag of padding (0)
                         0)       # minimal length of padding

    def test_min_length_with_invalid_length(self):
        with self.assertRaises(ValueError):
            fuzz_padding(ClientHelloGenerator(), min_length=257)

    def test_min_length_with_length_too_big_for_data(self):
        data_gen = fuzz_padding(ApplicationDataGenerator(b"text"),
                                min_length=254)

        data_msg = data_gen.generate(self.state)
        self.assertEqual(len(data_msg.write()), 4)

        with self.assertRaises(ValueError):
            self.state.msg_sock.sendMessageBlocking(data_msg)

    def test_xors(self):
        # packet with no modifications
        unchanged = bytearray(
                b'\x17\x03\x00\x000' # record layer header
                b'\xa1\xbb\x9f&Z\x1cb\xb3\xf3U\x11\xbb\xf4\xd6\x91\xf3'
                b'\xa8\xf2"\xb8\xa9@]\x16,\xc9\x17Wh\x17\x1e\xb5'
                b'\x9f\xcdm\x9a\xf0!\xe65\xea\xa8\xeb|(\xd8\xd2\x02')
        data_gen = fuzz_padding(ApplicationDataGenerator(b"text"),
                                min_length=16,
                                xors={-2:0xff})

        data_msg = data_gen.generate(self.state)
        self.state.msg_sock.sendMessageBlocking(data_msg)
        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(len(self.socket.sent[0]),
                         1 +        # record layer type
                         2 +        # protocol version
                         2 +        # record payload length field
                         4 +        # length of Application Data
                         160 // 8 + # length of HMAC
                         1 +        # size of length tag of padding (0)
                         23)        # minimal length of padding
        last_block = bytearray(
                b'\\Y\x90j\x8a\xe7\x82\xf3=\xceE\xe3\x0f\x85\x82\t')
        self.assertEqual(self.socket.sent[0], unchanged[:-16] + last_block)

class TestFuzzPlaintext(unittest.TestCase):
    def setUp(self):
        self.state = ConnectionState()
        self.socket = MockSocket(bytearray())

        defragger = defragmenter.Defragmenter()
        defragger.add_static_size(constants.ContentType.alert, 2)
        defragger.add_static_size(constants.ContentType.change_cipher_spec, 1)
        defragger.add_dynamic_size(constants.ContentType.handshake, 1, 3)
        self.state.msg_sock = messagesocket.MessageSocket(self.socket,
                                                          defragger)
        self.state.msg_sock.version = (3, 0)
        self.state.msg_sock.calcPendingStates(constants.CipherSuite.\
                                                TLS_RSA_WITH_AES_128_CBC_SHA,
                                              bytearray(48),
                                              bytearray(32),
                                              bytearray(32),
                                              None)
        self.state.msg_sock.changeWriteState()

    def test_xors(self):
        # packet with no modifications
        unchanged = bytearray(
                b'\x17\x03\x00\x00 ' # record layer header
                b'\xa1\xbb\x9f&Z\x1cb\xb3\xf3U\x11\xbb\xf4\xd6\x91\xf3'
                b'\xbf4\xd0\x86\x99\xb9\xd9Z\xc4_\x8db\xa7\xda\x1a\xea')
        data_gen = fuzz_plaintext(ApplicationDataGenerator(b"text"),
                                  xors={-2:0xff})

        data_msg = data_gen.generate(self.state)
        self.state.msg_sock.sendMessageBlocking(data_msg)
        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(len(self.socket.sent[0]),
                         1 +        # record layer type
                         2 +        # protocol version
                         2 +        # record payload length field
                         4 +        # length of Application Data
                         160 // 8 + # length of HMAC
                         1 +        # size of length tag of padding (0)
                         7)         # minimal length of padding
        last_block = bytearray(
                b'\x14\xa3\x14\xd2V+\x90\x08t\x81A%\xe5\xd5\xf4\x10')
        self.assertEqual(self.socket.sent[0], unchanged[:-16] + last_block)

    def test_substitutions(self):
        # packet with no modifications
        unchanged = bytearray(
                b'\x17\x03\x00\x00 ' # record layer header
                b'\xa1\xbb\x9f&Z\x1cb\xb3\xf3U\x11\xbb\xf4\xd6\x91\xf3'
                b'\xbf4\xd0\x86\x99\xb9\xd9Z\xc4_\x8db\xa7\xda\x1a\xea')
        data_gen = fuzz_plaintext(ApplicationDataGenerator(b"text"),
                                  substitutions={0:0xff})

        data_msg = data_gen.generate(self.state)
        self.state.msg_sock.sendMessageBlocking(data_msg)
        self.assertEqual(len(self.socket.sent), 1)
        self.assertEqual(len(self.socket.sent[0]),
                         1 +        # record layer type
                         2 +        # protocol version
                         2 +        # record payload length field
                         4 +        # length of Application Data
                         160 // 8 + # length of HMAC
                         1 +        # size of length tag of padding (0)
                         7)         # minimal length of padding
        # since we are doing the substitution on a CBC cipher in first block,
        # all subsequent blocks ciphertext is different too
        expected = bytearray(
                b'\xc0\\ba\x7f}Q\xe0\xa6\xc27P\xd7U\xdf\xf9'
                b'n\x97\xdf_\xe2\xef,X\x9b\rv[\x1c\x83\x1e\xbd')
        self.assertEqual(self.socket.sent[0][:5], unchanged[:5])
        self.assertEqual(self.socket.sent[0][5:], expected)


class TestSplitMessage(unittest.TestCase):
    def test_split_to_two(self):
        state = ConnectionState()
        vanilla_hello = ClientHelloGenerator().generate(state).write()
        fragments = []

        msg = ClientHelloGenerator()
        post_send = msg.post_send
        hello_gen = split_message(msg, fragments, 30)

        self.assertEqual(fragments, [])

        first_part = hello_gen.generate(state).write()

        self.assertEqual(len(first_part), 30)
        self.assertEqual(len(fragments), 2)
        self.assertEqual(len(fragments[0].write()), 13)
        self.assertEqual(fragments[1], post_send)

    def test_split_of_zero_length(self):
        # 0 length messages are intentionally unhandled
        fragments = []
        msg_gen = split_message(RawMessageGenerator(20, bytearray(0)),
                                fragments, 30)

        state = ConnectionState()
        with self.assertRaises(IndexError):
            msg_gen.generate(state)


class TestPopMessageFromList(unittest.TestCase):
    def test_with_message_list(self):
        msg_list = []

        msg_gen = PopMessageFromList(msg_list)

        msg_list.append(messages.Message(20, bytearray(b'\x20\x30')))
        msg_list.append(messages.Message(21, bytearray(b'\x30\x20')))

        msg = msg_gen.generate(None)

        self.assertEqual(msg.contentType, 20)
        self.assertEqual(msg.write(), bytearray(b'\x20\x30'))

        self.assertEqual(len(msg_list), 1)

    def test_with_post_send_call(self):
        msg_list = []

        msg_gen = PopMessageFromList(msg_list)

        msg_list.append(messages.Message(20, bytearray(b'\x20\x20')))
        post_send = mock.MagicMock()
        msg_list.append(post_send)

        msg = msg_gen.generate(None)

        self.assertEqual(msg.contentType, 20)
        self.assertEqual(msg.write(), bytearray(b'\x20\x20'))

        self.assertEqual(len(msg_list), 1)

        state = mock.Mock()
        msg_gen.post_send(state)

        post_send.assert_called_once_with(state)

        self.assertEqual(msg_list, [])


class TestFlushMessageList(unittest.TestCase):
    def test_with_message_list(self):
        msg_list = []

        msg_gen = FlushMessageList(msg_list)

        self.assertEqual(msg_list, [])

        msg_list.append(messages.Message(20, bytearray(b'\x20\x30')))
        msg_list.append(messages.Message(20, bytearray(b'\x60\x70')))

        msg = msg_gen.generate(None)

        self.assertEqual(msg.contentType, 20)
        self.assertEqual(msg.write(), bytearray(b'\x20\x30\x60\x70'))

        self.assertEqual(msg_list, [])

    def test_with_different_message_types(self):
        msg_list = [messages.Message(20, bytearray(b'\x20')),
                    messages.Message(30, bytearray(b'\x10'))]

        msg_gen = FlushMessageList(msg_list)

        with self.assertRaises(AssertionError):
            msg_gen.generate(None)

    def test_with_post_send_call(self):
        msg_list = []

        msg_gen = FlushMessageList(msg_list)

        msg_list.append(messages.Message(20, bytearray(b'\x20\x20')))
        msg_list.append(messages.Message(20, bytearray(b'\x30\x03')))
        post_send = mock.MagicMock()
        msg_list.append(post_send)

        msg = msg_gen.generate(None)

        self.assertEqual(msg.contentType, 20)
        self.assertEqual(msg.write(), bytearray(b'\x20\x20\x30\x03'))

        self.assertEqual(len(msg_list), 1)

        state = mock.Mock()
        msg_gen.post_send(state)

        post_send.assert_called_once_with(state)

        self.assertEqual(msg_list, [])


class TestFuzzPKCS1Padding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = generateRSAKey(1024)
        cls.key.old_addPKCS1Padding = cls.key._addPKCS1Padding

    def setUp(self):
        self.key._addPKCS1Padding = self.key.old_addPKCS1Padding

    def test_with_no_substitutions(self):
        fuzz_pkcs1_padding(self.key)
        for_signing = bytearray(range(0, 16))
        data = self.key._addPKCS1Padding(for_signing, 1)

        expected = bytearray([0, 1] + [0xff] * 109 + [0] + list(range(0, 16)))
        self.assertEqual(len(data), len(expected))
        self.assertEqual(data, expected)

    def test_with_substitutions(self):
        fuzz_pkcs1_padding(self.key, substitutions={1: 2})
        for_signing = bytearray(range(0, 16))
        data = self.key._addPKCS1Padding(for_signing, 1)

        expected = bytearray([0, 2] + [0xff] * 109 + [0] + list(range(0, 16)))
        self.assertEqual(len(data), len(expected))
        self.assertEqual(data, expected)

    def test_with_xors(self):
        fuzz_pkcs1_padding(self.key, xors={-1: 0x0f})
        for_signing = bytearray(range(1, 17))
        data = self.key._addPKCS1Padding(for_signing, 1)

        expected = bytearray([0, 1] + [0xff] * 109 + [0x0f] + list(range(1, 17)))
        self.assertEqual(len(data), len(expected))
        self.assertEqual(data, expected)

    def test_with_padding_byte(self):
        fuzz_pkcs1_padding(self.key, substitutions={1:2}, padding_byte=0xaa)
        for_signing = bytearray(range(5, 21))
        data = self.key._addPKCS1Padding(for_signing, 2)

        expected = bytearray([0, 2] + [0xaa] * 109 + [0x00] + list(range(5, 21)))
        self.assertEqual(len(data), len(expected))
        self.assertEqual(data, expected)


class TestReplacePlaintext(unittest.TestCase):
    def test_replace(self):
        state = ConnectionState()
        socket = MockSocket(bytearray())

        defragger = defragmenter.Defragmenter()
        state.msg_sock = messagesocket.MessageSocket(socket,
                                                     defragger)
        state.msg_sock.version = (3, 3)
        state.msg_sock.calcPendingStates(constants.CipherSuite.\
                                                TLS_RSA_WITH_AES_128_CBC_SHA,
                                              bytearray(48),
                                              bytearray(32),
                                              bytearray(32),
                                              None)
        state.msg_sock.changeWriteState()

        msg = ApplicationDataGenerator(bytearray(b"text"))
        msg = replace_plaintext(msg, bytearray(b'\x00' * 16))

        data_msg = msg.generate(state)

        state.msg_sock.sendMessageBlocking(data_msg)

        self.assertEqual(len(socket.sent), 1)
        self.assertEqual(len(socket.sent[0]),
                         1 +  # type
                         2 +  # proto version
                         2 +  # payload length
                         16)  # data length

        exp_data = bytearray(b'\x17\x03\x03\x00\x10'
                             b'H&\x1f\xc1\x9c\xde"\x92\xdd\xe4|\xfco)R\xd6')
        # just the fact that the ciphertext is smaller than the MAC size
        # indicates that it was completely replaced
        self.assertEqual(socket.sent[0], exp_data)

    def test_replace_with_replacement_not_multiple_of_cipher_block_size(self):
        state = ConnectionState()
        socket = MockSocket(bytearray())

        defragger = defragmenter.Defragmenter()
        state.msg_sock = messagesocket.MessageSocket(socket,
                                                     defragger)
        state.msg_sock.version = (3, 3)
        state.msg_sock.calcPendingStates(constants.CipherSuite.\
                                                TLS_RSA_WITH_AES_128_CBC_SHA,
                                              bytearray(48),
                                              bytearray(32),
                                              bytearray(32),
                                              None)
        state.msg_sock.changeWriteState()

        msg = ApplicationDataGenerator(b"text")
        msg = replace_plaintext(msg, b'\x00' * 8)

        data_msg = msg.generate(state)

        with self.assertRaises(ValueError):
            state.msg_sock.sendMessageBlocking(data_msg)


class TestHeartbeatGenerator(unittest.TestCase):
    def test___init__(self):
        hbg = HeartbeatGenerator(bytearray(b'payload'))

        self.assertIsNotNone(hbg)
        self.assertEqual(hbg.payload, bytearray(b'payload'))
        self.assertEqual(hbg.message_type,
                constants.HeartbeatMessageType.heartbeat_request)
        self.assertEqual(len(hbg.padding), 16)

    def test_generate(self):
        hbg = HeartbeatGenerator(bytearray(b'heartbeat test'))

        hb = hbg.generate(None)

        self.assertIsNotNone(hb)
        self.assertEqual(hb.payload, bytearray(b'heartbeat test'))
        self.assertEqual(hb.padding, hbg.padding)
        self.assertEqual(hb.message_type,
                constants.HeartbeatMessageType.heartbeat_request)

    def test_generate_with_small_padding(self):
        hbg = HeartbeatGenerator(bytearray(b''))
        hbg.padding = bytearray(b'\x00')

        hb = hbg.generate(None)

        self.assertEqual(hb.padding, bytearray(b'\x00'))

    def test_generate_with_no_padding(self):
        hbg = HeartbeatGenerator(bytearray(b''), padding_length=0)

        hb = hbg.generate(None)

        self.assertEqual(hb.padding, bytearray(b''))
