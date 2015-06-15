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

from tlsfuzzer.messages import ClientHelloGenerator
import tlslite.messages

class TestClientHelloGenerator(unittest.TestCase):
    def test___init__(self):
        chg = ClientHelloGenerator()

        self.assertIsNotNone(chg)
        self.assertEqual(chg.ciphers, [])

    def test_generate(self):
        chg = ClientHelloGenerator()

        with mock.patch.object(tlslite.messages.ClientHello, 'create',
                return_value=-33) as mock_method:
            ch = chg.generate(None)

        self.assertEqual(ch, -33)
        mock_method.assert_called_once_with((3, 3), bytearray(32), bytearray(0),
                                            [])
