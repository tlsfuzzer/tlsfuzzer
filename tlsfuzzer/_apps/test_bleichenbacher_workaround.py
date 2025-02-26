# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Bleichenbacher attack reproducer"""
from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

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
from tlslite.utils.dns_utils import is_valid_hostname
from tlslite.extensions import SNIExtension
from tlsfuzzer.utils.lists import natural_sort_keys


version = 3


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -t timeout     how long to wait before assuming the server won't")
    print("                send a message at incorrect time, 1.0s by default")
    print(" -n num         run 'num' or all(if 0) tests instead of default(50)")
    print("                (excluding \"sanity\" tests)")
    print(" -a desc        the expected alert description for invalid Finished")
    print("                messages - 20 (bad_record_mac) by default")
    print("                Note: other values are NOT RFC compliant!")
    print(" -l level       the expected alert level for invalid Finished")
    print("                - 2 (fatal) by default")
    print("                Note: other values are NOT RFC compliant!")
    print(" --no-safe-renego  Allow the server not to support safe")
    print("                renegotiation extension")
    print(" --no-sni       do not send server name extension.")
    print("                Sends extension by default if the hostname is a")
    print("                valid DNS name, not an IP address")
    print(" --help         this message")


def main():
    """Check if server is not vulnerable to Bleichenbacher attack"""
    host = "localhost"
    port = 4433
    num_limit = 50
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    timeout = 1.0
    alert = AlertDescription.bad_record_mac
    level = AlertLevel.fatal
    srv_extensions = {ExtensionType.renegotiation_info:None}
    no_sni = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:t:n:a:l:", ["help",
                                                        "no-safe-renego",
                                                        "no-sni"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '-t':
            timeout = float(arg)
        elif opt == '-a':
            alert = int(arg)
        elif opt == '-l':
            level = int(arg)
        elif opt == "--no-safe-renego":
            srv_extensions = None
        elif opt == "--no-sni":
            no_sni = True
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    cln_extensions = {ExtensionType.renegotiation_info:None}
    if is_valid_hostname(host) and not no_sni:
        cln_extensions[ExtensionType.server_name] = \
                SNIExtension().create(bytearray(host, 'ascii'))

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    # don't care which cipher, as long as it uses RSA key exchange
    ciphers = list(CipherSuite.certSuites)
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["set PKCS#1 padding type to 3 - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # set 2nd byte of padding to 3 (invalid value)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["set PKCS#1 padding type to 3 - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # set 2nd byte of padding to 1 (signing)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["set PKCS#1 padding type to 1 - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # set 2nd byte of padding to 1 (signing)
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["set PKCS#1 padding type to 1 - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # test early zero in random data
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["zero byte in random padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # test early zero in random data
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["zero byte in random padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if early padding separator is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["zero byte in last byte of random padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if early padding separator is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["zero byte in last byte of random padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if separator without any random padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["zero byte in first byte of random padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if separator without any random padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["zero byte in first byte of random padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if invalid first byte of encoded value is correctly detecte
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["invalid version number in padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if invalid first byte of encoded value is correctly detecte
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["invalid version number in padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no null separator in padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["no null separator in padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no null separator in padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["no null separator in padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no null separator in padding is detected
        # but with PMS set to non-zero
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["no null separator in encrypted value - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no null separator in padding is detected
        # but with PMS set to non-zero
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
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
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["no null separator in encrypted value - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short PMS is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(premaster_secret=bytearray([1, 1])))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["two byte long PMS (TLS version only) - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short PMS is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(premaster_secret=bytearray([1, 1])))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["two byte long PMS (TLS version only) - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no encrypted payload is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        # the TLS version is always set, so we mask the real padding separator
        # and set the last byte of PMS to 0
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-1:1},
                                                         premaster_secret=bytearray([1, 1, 0])))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["no encrypted value - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if no encrypted payload is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        # the TLS version is always set, so we mask the real padding separator
        # and set the last byte of PMS to 0
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-1:1},
                                                         premaster_secret=bytearray([1, 1, 0])))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["no encrypted value - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short encrypted payload is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        # the TLS version is always set, so we mask the real padding separator
        # and set the last byte of PMS to 0
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-1:1},
                                                         premaster_secret=bytearray([1, 1, 0, 3])))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["one byte encrypted value - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short encrypted payload is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        # the TLS version is always set, so we mask the real padding separator
        # and set the last byte of PMS to 0
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={-1:1},
                                                         premaster_secret=bytearray([1, 1, 0, 3])))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["one byte encrypted value - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short PMS is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(premaster_secret=bytearray([1]*47)))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["too short (47-byte) pre master secret - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short PMS is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(premaster_secret=bytearray([1]*47)))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["too short (47-byte) pre master secret - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short PMS is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(premaster_secret=bytearray([1]*4)))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["very short (4-byte) pre master secret - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short PMS is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(premaster_secret=bytearray([1]*4)))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["very short (4-byte) pre master secret - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation


        # check if too long PMS is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(premaster_secret=bytearray([1]*49)))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["too long (49-byte) pre master secret - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too long PMS is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(premaster_secret=bytearray([1]*49)))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["too long (49-byte) pre master secret - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if wrong TLS version number is rejected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(client_version=(2, 2)))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["wrong TLS version (2, 2) in pre master secret - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if wrong TLS version number is rejected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(client_version=(2, 2)))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["wrong TLS version (2, 2) in pre master secret - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if wrong TLS version number is rejected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        node = node.add_child(ClientKeyExchangeGenerator(client_version=(0, 0)))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["wrong TLS version (0, 0) in pre master secret - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if wrong TLS version number is rejected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator(client_version=(0, 0)))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["wrong TLS version (0, 0) in pre master secret - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short PKCS padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        # move the start of the padding forward, essentially encrypting two 0 bytes
        # at the beginning of the padding, but since those are transformed into a number
        # their existence is lost and it just like the padding was too small
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={1:0, 2:2}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["too short PKCS padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too short PKCS padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        # move the start of the padding forward, essentially encrypting two 0 bytes
        # at the beginning of the padding, but since those are transformed into a number
        # their existence is lost and it just like the padding was too small
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={1:0, 2:2}))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["too short PKCS padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too long PKCS padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(TCPBufferingEnable())
        # move the start of the padding backward, essentially encrypting no 0 bytes
        # at the beginning of the padding, but since those are transformed into a number
        # its lack is lost and it just like the padding was too big
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={0:2}))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\r\n\r\n")))
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["too long PKCS padding - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

        # check if too long PKCS padding is detected
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher]
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=cln_extensions))
        node = node.add_child(ExpectServerHello(extensions=srv_extensions))
        # in case the server does not support given cipher, it is acceptable
        # to abort connection here
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.handshake_failure)
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectServerHelloDone())
        # move the start of the padding backward, essentially encrypting no 0 bytes
        # at the beginning of the padding, but since those are transformed into a number
        # its lack is lost and it just like the padding was too big
        node = node.add_child(ClientKeyExchangeGenerator(padding_subs={0:2}))
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(ExpectNoMessage(timeout))
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["too long PKCS padding - with wait - {0}".format(CipherSuite.ietfNames[cipher])] = conversation

    # run the conversation
    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    if run_only:
        if num_limit > len(run_only):
            num_limit = len(run_only)
        regular_tests = [(k, v) for k, v in conversations.items() if k in run_only]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        exception = None
        try:
            runner.run()
        except Exception as exp:
            exception = exp
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if c_name in expected_failures:
            if res:
                xpass += 1
                xpassed.append(c_name)
                print("XPASS-expected failure but test passed\n")
            else:
                if expected_failures[c_name] is not None and  \
                    expected_failures[c_name] not in str(exception):
                        bad += 1
                        failed.append(c_name)
                        print("Expected error message: {0}\n"
                            .format(expected_failures[c_name]))
                else:
                    xfail += 1
                    print("OK-expected failure\n")
        else:
            if res:
                good += 1
                print("OK\n")
            else:
                bad += 1
                failed.append(c_name)

    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests) + 2*len(sanity_tests)))
    print("SKIP: {0}".format(len(run_exclude.intersection(conversations.keys()))))
    print("PASS: {0}".format(good))
    print("XFAIL: {0}".format(xfail))
    print("FAIL: {0}".format(bad))
    print("XPASS: {0}".format(xpass))
    print(20 * '=')
    sort = sorted(xpassed ,key=natural_sort_keys)
    if len(sort):
        print("XPASSED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))
    sort = sorted(failed, key=natural_sort_keys)
    if len(sort):
        print("FAILED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))

    if bad or xpass:
        sys.exit(1)

if __name__ == "__main__":
    main()
