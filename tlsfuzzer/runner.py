# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
from __future__ import print_function

from .messages import Connect, Close
from .expect import ExpectFinished
import socket

import tlslite.messages as litemessages
from tlslite.tlsrecordlayer import TLSRecordLayer
from tlslite.constants import ContentType
from tlslite.utils.compat import compat26Str
from tlslite.mathtls import calcMasterSecret, PRF_1_2


class Runner(object):
    def __init__(self, conversation):
        self.conversation = conversation

    def run(self):
        client_hello = None
        server_hello = None
        # server certificate message
        certificate = None
        for side, message in self.conversation.messages:
            if side == 'clnt':
                if isinstance(message, Connect):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((message.ip, message.port))

                    record_layer = TLSRecordLayer(sock)
                    if record_layer is None:
                        return False
                elif isinstance(message, Close):
                    record_layer = None
                    return True
                else:
                    msg = message.generate()

                    if isinstance(msg, litemessages.ClientHello):
                        print("sending ClientHello")
                        record_layer._handshakeStart(client=True)
                        record_layer.version = self.conversation.record_version
                        client_hello = msg
                    elif isinstance(msg, litemessages.ClientKeyExchange):
                        print("sending ClientKeyExchange")
                        # generate 48 random bytes
                        premasterSecret = bytearray(48)
                        premasterSecret[0] = client_hello.client_version[0]
                        premasterSecret[1] = client_hello.client_version[1]

                        public_key = \
                                certificate.certChain.getEndEntityPublicKey()
                        # TODO insert a pre-encrypt callback here
                        encryptedPremasterSecret =\
                                public_key.encrypt(premasterSecret)
                        msg.createRSA(encryptedPremasterSecret)
                    elif isinstance(msg, litemessages.ChangeCipherSpec):
                        print("sending ChangeCipherSpec")
                        master_secret = calcMasterSecret(
                                server_hello.server_version,
                                premasterSecret,
                                client_hello.random,
                                server_hello.random)
                        record_layer._calcPendingStates(
                                server_hello.cipher_suite,
                                master_secret,
                                client_hello.random,
                                server_hello.random,
                                None)
                    elif isinstance(msg, litemessages.Finished):
                        handshake_hashes =\
                                record_layer._handshake_sha256.digest()
                        verify_data = PRF_1_2(master_secret, b'client finished',
                                                handshake_hashes, 12)
                        msg.create(verify_data)
                        print("sending Finished")

                    print("message: {0!r}".format(message))
                    print("msg: {0!r}".format(msg))
                    for fuzz_message in message.serialise(msg):
                        for result in record_layer._sendMsg(fuzz_message):
                            if result in (0, 1):
                                raise Exception("blocked write")

                    if isinstance(msg, litemessages.ChangeCipherSpec):
                        record_layer._changeWriteState()

            elif side == 'srv':
                print("Waiting for {0}...".format(type(message)))

                if isinstance(message, ExpectFinished):
                    # TODO depend on cipher and TLS version negotiated
                    handshake_hashes =\
                            record_layer._handshake_sha256.digest()

                for result in record_layer._getNextRecord():
                    if result in (0, 1):
                        raise Exception("blocking read")
                    else: break
                header, parser = result

                if header.type != message.contentType:
                    return False

                # parse message and compare to expected values
                msg = message.parse(parser)
                print("msg: {0!r}".format(msg))

                if header.type == ContentType.handshake:
                    print("updating handshake hashes")
                    compat_bytes = compat26Str(parser.bytes)
                    record_layer._handshake_md5.update(compat_bytes)
                    record_layer._handshake_sha.update(compat_bytes)
                    record_layer._handshake_sha256.update(compat_bytes)

                if isinstance(msg, litemessages.ServerHello):
                    print("got ServerHello")

                    server_hello = msg
                    record_layer.version = server_hello.server_version
                elif isinstance(msg, litemessages.Certificate):
                    print("got Certificate")

                    certificate = msg
                elif isinstance(msg, litemessages.ServerHelloDone):
                    print("got ServerHelloDone")
                elif isinstance(msg, litemessages.ChangeCipherSpec):
                    print("got ChangeCipherSpec")
                    record_layer._changeReadState()
                elif isinstance(msg, litemessages.Finished):
                    print("got Finished")

                    verify_data = PRF_1_2(master_secret, b'server finished',
                                            handshake_hashes, 12)

                    # TODO: raise better exception
                    assert(verify_data == msg.verify_data)
                    record_layer._handshakeDone(resumed=False)
                else:
                    assert(False)

        return True


