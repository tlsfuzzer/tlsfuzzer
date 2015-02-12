# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from tlsfuzzer.messages import Connect, ClientHelloGenerator,\
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator,\
        FinishedGenerator, AlertGenerator, Close
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate,\
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished

from tlslite.constants import CipherSuite

class Conversation(object):
    def __init__(self):
        self.messages = []
        self.record_version = (3, 1)

class Generator(object):
    def __init__(self, fingerprint=None):
        """
        @param fingerprint: result of fingerprinting the server (server config)
        """
        self.fingerprint = fingerprint

    def __iter__(self):
        """
        @return: iterator of the test cases available
        """
        conv = Conversation()
        conv.messages.append(('clnt', Connect(\
                self.fingerprint.ip, self.fingerprint.port)))
        conv.messages.append(('clnt', ClientHelloGenerator(\
                ciphers=[CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA])))
        conv.messages.append(('srv', ExpectServerHello()))
        conv.messages.append(('srv', ExpectCertificate()))
        conv.messages.append(('srv', ExpectServerHelloDone()))
        conv.messages.append(('clnt', ClientKeyExchangeGenerator()))
        conv.messages.append(('clnt', ChangeCipherSpecGenerator()))
        conv.messages.append(('clnt', FinishedGenerator()))
        conv.messages.append(('srv', ExpectChangeCipherSpec()))
        conv.messages.append(('srv', ExpectFinished()))
        conv.messages.append(('clnt', AlertGenerator()))
        conv.messages.append(('clnt', Close()))
        yield conv


