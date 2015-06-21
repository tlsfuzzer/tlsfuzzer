# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.messages import ClientHello
from tlslite.constants import CipherSuite
from tlsfuzzer.badserver import ServerSettings, BadServer, ServerStop

class TestServerSettings(unittest.TestCase):
    def test___init__(self):
        settings = ServerSettings()

        self.assertIsNotNone(settings)
        self.assertEqual(settings.supported_versions,
                         [(3, 0), (3, 1), (3, 2), (3, 3)])
        self.assertFalse(settings.record_layer_ver_intolerance)
        self.assertFalse(settings.tls_version_intolerance)
        self.assertFalse(settings.extension_intolerance)

    def test_test_record_layer_version(self):
        settings = ServerSettings()

        settings.test_record_layer_version((4, 6))
        settings.test_record_layer_version((3, 1))
        settings.test_record_layer_version((3, 0))

    def test_test_record_layer_version_with_intolerance(self):
        settings = ServerSettings()
        settings.record_layer_ver_intolerance = True
        settings.record_layer_ver_ok = [(3, 0), (3, 1)]

        settings.test_record_layer_version((3, 0))
        settings.test_record_layer_version((3, 1))

        with self.assertRaises(ServerStop):
            settings.test_record_layer_version((3, 3))

        with self.assertRaises(ServerStop):
            settings.test_record_layer_version((2, 0))

    def test_test_record_layer_version_with_callback(self):
        self.called = False
        def callback(version):
            self.assertEqual(version, (3, 3))
            self.called = True

        settings = ServerSettings()
        settings.record_layer_ver_intolerance = True
        settings.record_layer_ver_cb = callback

        self.assertFalse(self.called)

        settings.test_record_layer_version((3, 3))

        self.assertTrue(self.called)

    def test_test_client_hello(self):
        settings = ServerSettings()

        client_hello = ClientHello()

        settings.test_client_hello(client_hello)

    def test_test_client_hello_with_version_intolerance(self):
        settings = ServerSettings()
        settings.tls_version_intolerance = True
        settings.tls_version_intolerance_ok = [(3, 0), (3, 1)]

        client_hello = ClientHello()

        client_hello.client_version = (3, 1)
        settings.test_client_hello(client_hello)

        client_hello.client_version = (3, 3)
        with self.assertRaises(ServerStop):
            settings.test_client_hello(client_hello)

    def test_test_client_hello_with_callback(self):
        self.called = False
        def callback(version):
            self.assertEqual(version, (3, 3))
            self.called = True

        settings = ServerSettings()
        settings.tls_version_intolerance = True
        settings.tls_version_intolerance_cb = callback

        client_hello = ClientHello()

        client_hello.client_version = (3, 3)

        self.assertFalse(self.called)
        settings.test_client_hello(client_hello)
        self.assertTrue(self.called)

    def test_test_client_hello_with_extensions(self):
        settings = ServerSettings()
        settings.extension_intolerance = True

        client_hello = ClientHello()
        self.assertIsNone(client_hello.extensions)

        settings.test_client_hello(client_hello)

        client_hello.extensions = [None]

        with self.assertRaises(ServerStop):
            settings.test_client_hello(client_hello)

    def test_test_client_hello_with_empty_extensions(self):
        settings = ServerSettings()
        settings.empty_ext_list_intolerance = True

        client_hello = ClientHello()
        self.assertIsNone(client_hello.extensions)

        settings.test_client_hello(client_hello)

        client_hello.extensions = []

        with self.assertRaises(ServerStop):
            settings.test_client_hello(client_hello)

    def test_select_version(self):
        settings = ServerSettings()

        self.assertEqual(settings.select_version((3, 2)), (3, 2))

        self.assertEqual(settings.select_version((3, 4)), (3, 3))

        settings.supported_versions = [(3, 1), (3, 3)]

        self.assertEqual(settings.select_version((3, 2)), (3, 1))

        with self.assertRaises(ServerStop):
            settings.select_version((3, 0))

    def test_select_cipher(self):
        settings = ServerSettings()

        self.assertEqual(settings.cipher_ordering, ServerSettings.CLIENT_SIDE)

        client_hello = ClientHello()
        client_hello.cipher_suites = [CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                                      CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]

        self.assertEqual(settings.select_cipher((3, 3), client_hello),
                         CipherSuite.TLS_RSA_WITH_RC4_128_SHA)

    def test_select_cipher_with_server_side_ordering(self):
        settings = ServerSettings()
        settings.cipher_ordering = ServerSettings.SERVER_SIDE

        client_hello = ClientHello()
        client_hello.cipher_suites = [CipherSuite.TLS_RSA_WITH_RC4_128_SHA,
                                      CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]

        self.assertEqual(settings.select_cipher((3, 3), client_hello),
                         CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)

    def test_select_cipher_with_invalid_ordering(self):
        settings = ServerSettings()
        settings.cipher_ordering = -1

        client_hello = ClientHello()
        client_hello.cipher_suites = [CipherSuite.TLS_RSA_WITH_RC4_128_SHA]

        with self.assertRaises(AssertionError):
            settings.select_cipher((3, 0), client_hello)

    def test_select_cipher_with_unknown_cipher(self):
        settings = ServerSettings()

        client_hello = ClientHello()
        client_hello.cipher_suites = [0xfff0, 0xfff1]

        with self.assertRaises(ServerStop):
            settings.select_cipher((3, 3), client_hello)

    def test_select_extensions(self):
        settings = ServerSettings()

        client_hello = ClientHello()
        client_hello.client_version = (3, 3)

        self.assertIsNone(settings.select_extensions((3, 3), 0x4, client_hello))

    def test_select_compression(self):
        settings = ServerSettings()

        client_hello = ClientHello()

        self.assertEqual(settings.select_compression((3, 3), 0x4, client_hello),
                         0)

class TestBadServer(unittest.TestCase):
    def test___init__(self):
        bad_server = BadServer(None, None)

        self.assertIsNotNone(bad_server)
