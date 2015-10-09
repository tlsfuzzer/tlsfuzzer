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

from tlsfuzzer.messages import ClientHelloGenerator, ClientKeyExchangeGenerator,\
        ChangeCipherSpecGenerator, FinishedGenerator, \
        RenegotiationInfoExtension, ResetHandshakeHashes, SetMaxRecordSize, \
        pad_handshake, truncate_handshake, Close, fuzz_message, \
        RawMessageGenerator, split_message, PopMessageFromList, \
        FlushMessageList
from tlsfuzzer.runner import ConnectionState
import tlslite.messages as messages
import tlslite.extensions as extensions
import tlslite.utils.keyfactory as keyfactory
import tlslite.constants as constants
from tlslite.utils.codec import Parser


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

    def test_generate_extensions_with_empty_extensions(self):
        state = ConnectionState()
        chg = ClientHelloGenerator(extensions={0x1234:None})

        return_val = mock.MagicMock()
        return_val.write = mock.MagicMock(return_value=bytearray(10))
        with mock.patch.object(messages.ClientHello, 'create',
                return_value=return_val) as mock_method:
            ch = chg.generate(state)

        self.assertEqual(ch, return_val)
        ext = extensions.TLSExtension().create(0x1234, bytearray(0))
        mock_method.assert_called_once_with((3, 3), bytearray(32), bytearray(0),
                                            [],
                                            extensions=[ext])

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

    def test_generate_extensions_with_renego_info_default_generator(self):
        state = ConnectionState()
        state.client_verify_data = bytearray(b'\xab\xcd')
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

class TestClientKeyExchangeGenerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key = keyfactory.generateRSAKey(1024)

    def test___init__(self):
        cke = ClientKeyExchangeGenerator()

        self.assertEqual(len(cke.premaster_secret), 48)

    def test_generate(self):
        state = ConnectionState()
        state.get_server_public_key = lambda : self.priv_key
        cke = ClientKeyExchangeGenerator()

        ret = cke.generate(state)

        self.assertEqual(len(ret.encryptedPreMasterSecret), 128)
        decrypt = self.priv_key.decrypt(ret.encryptedPreMasterSecret)

        self.assertEqual(decrypt[:2], bytearray([3, 3]))

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

class TestFinishedGenerator(unittest.TestCase):
    def test___init__(self):
        fg = FinishedGenerator()

        self.assertIsNotNone(fg)

    def test_generate(self):
        fg = FinishedGenerator()
        state = ConnectionState()

        ret = fg.generate(state)

        self.assertIsInstance(ret, messages.Finished)

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

class TestSplitMessage(unittest.TestCase):
    def test_split_to_two(self):
        state = ConnectionState()
        vanilla_hello = ClientHelloGenerator().generate(state).write()
        fragments = []
        hello_gen = split_message(ClientHelloGenerator(), fragments, 30)

        self.assertEqual(fragments, [])

        first_part = hello_gen.generate(state).write()

        self.assertEqual(len(first_part), 30)
        self.assertEqual(len(fragments), 1)

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
