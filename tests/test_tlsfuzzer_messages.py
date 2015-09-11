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
        ChangeCipherSpecGenerator, FinishedGenerator
from tlsfuzzer.runner import ConnectionState
import tlslite.messages as messages
import tlslite.utils.keyfactory as keyfactory
import tlslite.constants as constants

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
                                            [])

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
