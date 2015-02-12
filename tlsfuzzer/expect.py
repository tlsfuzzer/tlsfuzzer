# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

from tlslite.constants import ContentType, HandshakeType, CertificateType
from tlslite.messages import ServerHello, Certificate, ServerHelloDone,\
        ChangeCipherSpec, Finished

class Expect(object):
    pass

class ExpectServerHello(Expect):
    def __init__(self):
        self.contentType = ContentType.handshake

    def parse(self, parser):
        """
        @type parser: Parser
        """
        t = parser.get(1)
        if t != HandshakeType.server_hello:
            raise Exception("Unexpected handshake message type: {0}".format(t))
        sh = ServerHello()
        return sh.parse(parser)

class ExpectCertificate(Expect):
    def __init__(self, certType=CertificateType.x509):
        self.contentType = ContentType.handshake
        self.certType = certType

    def parse(self, parser):
        """
        @type parser: Parser
        """
        t = parser.get(1)
        if t != HandshakeType.certificate:
            raise Exception("Unexpected handshake message type: {0}".format(t))
        c = Certificate(self.certType)
        return c.parse(parser)

class ExpectServerHelloDone(Expect):
    def __init__(self):
        self.contentType = ContentType.handshake

    def parse(self, parser):
        """
        @type parser: Parser
        """
        t = parser.get(1)
        if t != HandshakeType.server_hello_done:
            raise Exception("Unexpected handhsake message type: {0}".format(t))
        d = ServerHelloDone()
        return d.parse(parser)

class ExpectChangeCipherSpec(Expect):
    def __init__(self):
        self.contentType = ContentType.change_cipher_spec

    def parse(self, parser):
        """
        @type parser: Parser
        """
        return ChangeCipherSpec().parse(parser)

class ExpectFinished(Expect):
    def __init__(self, version=(3, 3)):
        self.contentType = ContentType.handshake
        self.version = version

    def parse(self, parser):
        """
        @type parser: Parser
        """
        t = parser.get(1)
        if t != HandshakeType.finished:
            raise Exception("Unexpected handshake message type: {0}".format(t))
        f = Finished(self.version)
        return f.parse(parser)

