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
        ExpectFinished

from tlslite.constants import ContentType, HandshakeType
from tlslite.messages import Message

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

