# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Bleichenbacher attack reproducer"""
from __future__ import print_function
import traceback
import sys
import getopt

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        TCPBufferingEnable, TCPBufferingDisable, TCPBufferingFlush
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectApplicationData, ExpectNoMessage

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -t timeout     how long to wait before assuming the server won't")
    print("                send a message at incorrect time, 1.0s by default")
    print(" --help         this message")


def main():
    """Check if server is not vulnerable to Bleichenbacher attack"""
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    timeout = 1.0

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:t:", ["help"])
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
        elif opt == '-t':
            timeout = float(arg)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())

    conversations["sanity"] = conversation

    for cipher in CipherSuite.certSuites:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())

        conversations["sanity - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if a certain number doesn't trip up the server
        # (essentially a second sanity test)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={2:1}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())

        conversations["static non-zero byte in random padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # set 2nd byte of padding to 3 (invalid value)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={1:3}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["set PKCS#1 padding type to 3 - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # set 2nd byte of padding to 3 (invalid value)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={1:3}))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["set PKCS#1 padding type to 3 - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # set 2nd byte of padding to 1 (signing)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={1:1}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["set PKCS#1 padding type to 1 - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # set 2nd byte of padding to 1 (signing)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={1:1}))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["set PKCS#1 padding type to 1 - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # test early zero in random data
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={4:0}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["zero byte in random padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # test early zero in random data
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={4:0}))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["zero byte in random padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if early padding separator is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-2:0}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["zero byte in last byte of random padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if early padding separator is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-2:0}))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["zero byte in last byte of random padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if separator without any random padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={2:0}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["zero byte in first byte of random padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if separator without any random padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={2:0}))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["zero byte in first byte of random padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if invalid first byte of encoded value is correctly detecte
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={0:1}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["invalid version number in padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if invalid first byte of encoded value is correctly detecte
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={0:1}))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["invalid version number in padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no null separator in padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-1:1}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["no null separator in padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no null separator in padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-1:1}))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["no null separator in padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no null separator in padding is detected
        # but with PMS set to non-zero
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-1:1},
                                                         premaster_secret=bytearray([1]*48)))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["no null separator in encrypted value - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no null separator in padding is detected
        # but with PMS set to non-zero
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions={ExtensionType.renegotiation_info:None}))
        node = node.add_child(ExpectServerHello(extensions={ExtensionType.renegotiation_info:None}))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-1:1},
                                                         premaster_secret=bytearray([1]*48)))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
        node.add_child(ExpectClose())

        conversations["no null separator in encrypted value - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

    good = 0
    bad = 0

    for c_name, c_test in conversations.items():
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
            print("")
            res = False

        if res:
            good+=1
            print("OK\n")
        else:
            bad+=1

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
