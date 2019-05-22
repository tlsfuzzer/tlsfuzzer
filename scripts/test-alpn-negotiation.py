# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        fuzz_message, ResetHandshakeHashes, Close, ResetRenegotiationInfo
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType
from tlslite.extensions import ALPNExtension, TLSExtension


def natural_sort_keys(s, _nsre=re.compile('([0-9]+)')):
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(_nsre, s)]


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    run_exclude = set()

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["only http/1.1"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.')])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.no_application_protocol))
    node.add_child(ExpectClose())
    conversations["only http/1."] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.X')])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.no_application_protocol))
    node.add_child(ExpectClose())
    conversations["only http/1.X"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.'),
                                                       bytearray(b'http/1.1')])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["http/1. and http/1.1"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'')])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["empty element"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create([])}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["empty list"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: TLSExtension(extType=ExtensionType.alpn).create(bytearray())}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node.add_child(ExpectClose())
    conversations["empty extension"] = conversation

    # underflow length of "protocol_name_list" test
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1'),
                                                       bytearray(b'http/2')])}
    msg = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    # -17 is position of second byte in 2 byte long length of "protocol_name_list"
    # setting it to value of 9 (bytes) will hide the second item in the "protocol_name_list"    
    node = node.add_child(fuzz_message(msg, substitutions={-17: 9}))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["underflow length of protocol_name_list"] = conversation

    # overflow length of "protocol_name_list" test
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1'),
                                                       bytearray(b'http/2')])}
    msg = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    # -17 is position of second byte in 2 byte long length of "protocol_name_list"
    # setting it to value of 18 (bytes) will raise the length value for 2 more bytes    
    node = node.add_child(fuzz_message(msg, substitutions={-17: 18}))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["overflow length of protocol_name_list"] = conversation

    # overflow length of last item in "protocol_name_list" test
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1'),
                                                       bytearray(b'http/2')])}
    msg = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    # -7 is position of a length (1 byte long) for the last item in "protocol_name_list"
    # setting it to value of 8 (bytes) will raise the length value for 2 more bytes  
    node = node.add_child(fuzz_message(msg, substitutions={-7: 8}))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.decode_error))
    node = node.add_child(ExpectClose())
    conversations["overflow length of last item"] = conversation

    # renegotiation with protocol change
    conversation = Connect(host, port)
    node = conversation

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/2')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, session_id=bytearray(0), extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/2')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())

    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["renegotiation with protocol change"] = conversation

    # renegotiation without protocol change
    conversation = Connect(host, port)
    node = conversation

    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, session_id=bytearray(0), extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())

    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["renegotiation without protocol change"] = conversation

    # renegotiation 2nd handshake alpn
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # 2nd handshake
    node = node.add_child(ResetHandshakeHashes())
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, session_id=bytearray(0), extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())

    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["renegotiation 2nd handshake alpn"] = conversation

    # resumption without alpn change

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    close.add_child(node)

    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info:None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext, resume=True))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())

    conversations["resumption without alpn change"] = conversation

    # resumption with alpn change

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    close.add_child(node)

    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'h2')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info:None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'h2')])}
    node = node.add_child(ExpectServerHello(extensions=ext, resume=True))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())

    conversations["resumption with alpn change"] = conversation

    # resumption with alpn 

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    ext = {ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    close = ExpectClose()
    node.next_sibling = close
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    close.add_child(node)

    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    ext = {ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')]),
	   ExtensionType.renegotiation_info:None}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info:None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext, resume=True))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())

    conversations["resumption with alpn"] = conversation

    # 16269 byte long array and 255 byte long items test
    # Client Hello longer than 2^14 bytes issue
    conversation = Connect(host, port)
    node = conversation
    proto = bytearray(b"A" * 255)
    lista = []
    lista.append(proto)
    # 63 items 255 bytes long + 1 item 195 bytes long + 1 item 8 byte long (http/1.1)
    for p in range(1,63):
        lista.append(proto)
    # 195 + 1 byte to reproduce the issue 
    lista.append(bytearray(b'B' * 196))
    lista.append(bytearray(b'http/1.1'))
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {ExtensionType.alpn: ALPNExtension().create(lista)}
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    ext = {ExtensionType.renegotiation_info: None,
           ExtensionType.alpn: ALPNExtension().create([bytearray(b'http/1.1')])}
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["16269 byte long array"] = conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_test = ('sanity', conversations['sanity'])
    ordered_tests = chain([sanity_test],
                          filter(lambda x: x[0] != 'sanity',
                                 conversations.items()),
                          [sanity_test])

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        try:
            runner.run()
        except:
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(c_name)

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
