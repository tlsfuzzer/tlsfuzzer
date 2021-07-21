# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Bleichenbacher attack reproducer with timing side-channel check"""
from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.timing_runner import TimingRunner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
    ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
    FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
    TCPBufferingEnable, TCPBufferingDisable, TCPBufferingFlush, fuzz_mac, \
    fuzz_padding
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
    ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
    ExpectAlert, ExpectClose, ExpectApplicationData, ExpectNoMessage

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
    ExtensionType
from tlslite.utils.dns_utils import is_valid_hostname
from tlslite.extensions import SNIExtension, SignatureAlgorithmsCertExtension,\
    SignatureAlgorithmsExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.helpers import SIG_ALL, RSA_PKCS1_ALL


version = 13


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
    print(" -C cipher      specify cipher for connection. Use integer value")
    print("                or IETF name. Integer must be prefixed with '0x'")
    print("                if it is hexadecimal. By default uses")
    print("                TLS_RSA_WITH_AES_128_CBC_SHA ciphersuite.")
    print(" -i interface   Allows recording timing information")
    print("                on specified interface. Required to enable timing tests")
    print(" -o dir         Specifies output directory for timing information")
    print("                /tmp by default")
    print(" --repeat rep   How many timing samples should be gathered for each test")
    print("                100 by default")
    print(" --no-safe-renego  Allow the server not to support safe")
    print("                renegotiation extension")
    print(" --no-sni       do not send server name extension.")
    print("                Sends extension by default if the hostname is a")
    print("                valid DNS name, not an IP address")
    print(" --cpu-list     Set the CPU affinity for the tcpdump process")
    print("                See taskset(1) man page for the syntax of this")
    print("                option. Not used by default.")
    print(" --static-enc   Re-use once generated RSA ciphertext. This may make the")
    print("                timing signal weaker or stronger depending on implementation.")
    print("                By default ciphertexts that have padding will be randomised.")
    print(" --help         this message")


def main():
    """Check if server is not vulnerable to Bleichenbacher attack"""
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    timeout = 1.0
    alert = AlertDescription.bad_record_mac
    level = AlertLevel.fatal
    srv_extensions = {ExtensionType.renegotiation_info: None}
    no_sni = False
    repetitions = 100
    interface = None
    timing = False
    outdir = "/tmp"
    cipher = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    affinity = None
    reuse_rsa_ciphertext = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv,
                               "h:p:e:x:X:t:n:a:l:l:o:i:C:",
                               ["help",
                                "no-safe-renego",
                                "no-sni",
                                "repeat=",
                                "cpu-list=",
                                "static-enc"])
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
        elif opt == '-C':
            if arg[:2] == '0x':
                cipher = int(arg, 16)
            else:
                try:
                    cipher = getattr(CipherSuite, arg)
                except AttributeError:
                    cipher = int(arg)
        elif opt == '-t':
            timeout = float(arg)
        elif opt == '-a':
            alert = int(arg)
        elif opt == '-l':
            level = int(arg)
        elif opt == "-i":
            timing = True
            interface = arg
        elif opt == '-o':
            outdir = arg
        elif opt == "--repeat":
            repetitions = int(arg)
        elif opt == "--no-safe-renego":
            srv_extensions = None
        elif opt == "--no-sni":
            no_sni = True
        elif opt == "--cpu-list":
            affinity = arg
        elif opt == "--static-enc":
            reuse_rsa_ciphertext = True
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    cln_extensions = {ExtensionType.renegotiation_info: None}
    if is_valid_hostname(host) and not no_sni:
        cln_extensions[ExtensionType.server_name] = \
            SNIExtension().create(bytearray(host, 'ascii'))
    cln_extensions[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(RSA_PKCS1_ALL)
    cln_extensions[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)

    # RSA key exchange check
    if cipher not in CipherSuite.certSuites:
        print("Ciphersuite has to use RSA key exchange.")
        exit(1)

    conversations = OrderedDict()

    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
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

    runner = Runner(conversation)
    try:
        runner.run()
    except Exception as exp:
        # Exception means the server rejected the ciphersuite
        print("Failing on {0} because server does not support it. ".format(CipherSuite.ietfNames[cipher]))
        print(20 * '=')
        exit(1)

    # check if a certain number doesn't trip up the server
    # (essentially a second sanity test)
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator(padding_subs={2: 1}))
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

    conversations["sanity - static non-zero byte in random padding"] = conversation

    # create a CKE with PMS the runner doesn't know/use
    # (benchmark to measure other tests to)
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    # use too short PMS but then change padding so that the PMS is
    # correct length with correct TLS version but the encryption keys
    # that tlsfuzzer calculates will be incorrect
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={-3: 0, -2: 3, -1: 3},
        premaster_secret=bytearray([0] * 46),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["fuzzed pre master secret"] = conversation

    # set 2nd byte of padding to 3 (invalid value)
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={1: 3},
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["set PKCS#1 padding type to 3"] = conversation

    # set 2nd byte of padding to 1 (signing)
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={1: 1},
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["set PKCS#1 padding type to 1"] = conversation

    # use the padding for signing (type 1)
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={1: 1},
        padding_byte=0xff,
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["use PKCS#1 padding type 1"] = conversation

    # test early zero in random data
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={4: 0},
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["zero byte in random padding"] = conversation

    # check if early padding separator is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={-2: 0},
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["zero byte in last byte of random padding"] = conversation

    # check if separator without any random padding is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={2: 0},
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["zero byte in first byte of random padding"] = conversation

    # check if invalid first byte of encoded value is correctly detecte
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={0: 1},
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["invalid version number in padding"] = conversation

    # check if no null separator in padding is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={-1: 1},
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["no null separator in padding"] = conversation

    # check if no null separator in padding is detected
    # but with PMS bytes set to non-zero
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={-1: 1},
        premaster_secret=bytearray([3, 3]),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["no null separator in encrypted value"] = conversation

    # completely random plaintext
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={-1: 0xaf,
                      0: 0x27,
                      1: 0x09},
        premaster_secret=bytearray([3, 3]),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["random plaintext"] = conversation

    # check if too short PMS is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        premaster_secret=bytearray([1, 1]),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["two byte long PMS (TLS version only)"] = conversation

    # check if no encrypted payload is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    # the TLS version is always set, so we mask the real padding separator
    # and set the last byte of PMS to 0
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={-1: 1},
        premaster_secret=bytearray([1, 1, 0]),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["no encrypted value"] = conversation

    # check if too short encrypted payload is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    # the TLS version is always set, so we mask the real padding separator
    # and set the last byte of PMS to 0
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={-1: 1},
        premaster_secret=bytearray([1, 1, 0, 3]),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["one byte encrypted value"] = conversation

    # check if too short PMS is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        premaster_secret=bytearray([0] * 47),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["too short (47-byte) pre master secret"] = conversation

    # check if too short PMS is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        premaster_secret=bytearray([0] * 4),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very short (4-byte) pre master secret"] = conversation

    # check if too long PMS is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        premaster_secret=bytearray([0] * 49),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["too long (49-byte) pre master secret"] = conversation

    # check if very long PMS is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        premaster_secret=bytearray([0] * 124),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very long (124-byte) pre master secret"] = conversation

    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        premaster_secret=bytearray([0] * 96),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very long (96-byte) pre master secret"] = conversation

    # check if wrong TLS version number is rejected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        client_version=(2, 2),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["wrong TLS version (2, 2) in pre master secret"] = conversation

    # check if wrong TLS version number is rejected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        client_version=(0, 0),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["wrong TLS version (0, 0) in pre master secret"] = conversation

    # check if too short PKCS padding is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    # move the start of the padding forward, essentially encrypting two 0 bytes
    # at the beginning of the padding, but since those are transformed into a number
    # their existence is lost and it just like the padding was too small
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={1: 0, 2: 2},
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["too short PKCS padding"] = conversation

    # check if very short PKCS padding doesn't have a different behaviour
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    # move the start of the padding 40 bytes towards LSB
    subs = {}
    for i in range(41):
        subs[i] = 0
    subs[41] = 2
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs=subs,
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very short PKCS padding (40 bytes short)"] = conversation

    # check if too long PKCS padding is detected
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    # move the start of the padding backward, essentially encrypting no 0 bytes
    # at the beginning of the padding, but since those are transformed into a number
    # its lack is lost and it just like the padding was too big
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={0: 2},
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["too long PKCS padding"] = conversation

    # test for Hamming weight sensitivity:
    # very low Hamming weight:
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_byte=0,
        client_version=(0, 0),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very low Hamming weight RSA plaintext"] = conversation

    # low Hamming weight:
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={-1: 1},
        padding_byte=1,
        client_version=(1, 1),
        premaster_secret=bytearray([1]*48),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["low Hamming weight RSA plaintext"] = conversation

    # test for Hamming weight sensitivity:
    # very high Hamming weight:
    conversation = Connect(host, port)
    node = conversation
    ciphers = [cipher]
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               extensions=cln_extensions))
    node = node.add_child(ExpectServerHello(extensions=srv_extensions))

    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(TCPBufferingEnable())
    node = node.add_child(ClientKeyExchangeGenerator(
        padding_subs={-1: 0xff},
        padding_byte=0xff,
        client_version=(0xff, 0xff),
        premaster_secret=bytearray([0xff]*48),
        reuse_encrypted_premaster=reuse_rsa_ciphertext))
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very high Hamming weight RSA plaintext"] = conversation

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
    if num_limit < len(conversations):
        sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    else:
        sampled_tests = regular_tests
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    print("Running tests for {0}".format(CipherSuite.ietfNames[cipher]))

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
                if expected_failures[c_name] is not None and \
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
    print("""Tests for handling of malformed encrypted values in CKE

This test script checks if the server correctly handles malformed
Client Key Exchange messages in RSA key exchange.
When executed with `-i` it will also verify that different errors
are rejected in the same amount of time; it checks for timing
sidechannel.
The script executes tests without \"sanity\" in name multiple
times to estimate server response time.

Quick reminder: when encrypting a value using PKCS#1 v1.5 standard
the plaintext has the following structure, starting from most
significant byte:
- one byte, the version of the encryption, must be 0
- one byte, the type of encryption, must be 2 (is 1 in case of
  signature)
- one or more bytes of random padding, with no zero bytes. The
  count must equal the byte size of the public key modulus less
  size of encrypted value and 3 (for version, type and separator)
  For signatures the bytes must equal 0xff
- one zero byte that acts as separator between padding and
  encrypted value
- one or more bytes that are the encrypted value, for TLS it must
  be 48 bytes long and the first two bytes need to equal the
  TLS version advertised in Client Hello

All tests should exhibit the same kind of timing behaviour, but
if some groups of tests are inconsistent, that points to likely
place where the timing leak happens:
- the control test case:
  - 'fuzzed pre master secret' - this will end up with random
    plaintexts in record with Finished, most resembling a randomly
    selected PMS by the server
  - 'random plaintext' - this will end up with a completely random
    plaintext after RSA decryption, most resembling a ciphertext
    for which the Bleichenbacher oracle needs a negative result
- padding type verification:
  - 'set PKCS#1 padding type to 3'
  - 'set PKCS#1 padding type to 1'
  - 'use PKCS#1 padding type 1'
- incorrect size of encrypted value (pre-master secret),
  inconsistent results here suggests that the decryption leaks
  length of plaintext:
  - 'zero byte in random padding' - this creates a PMS that's 4
    bytes shorter than the public key size and has a random TLS
    version
  - 'zero byte in last byte of random padding' - this creates a
    PMS that's one byte too long (49 bytes long), with a TLS
    version that's (0, major_version)
  - 'no null separator in padding' - as the PMS is all zero, this
    effectively sends a PMS that's 45 bytes long with TLS version
    of (0, 0)
  - 'two byte long PMS (TLS version only)'
  - 'one byte encrypted value' - the encrypted value is 3, as a
    correct value for first byte of TLS version
  - 'too short (47-byte) pre master secret'
  - 'very short (4-byte) pre master secret'
  - 'too long (49-byte) pre master secret'
  - 'very long (124-byte) pre master secret'
  - 'very long (96-byte) pre master secret'
- invalid PKCS#1 v1.5 encryption padding:
  - 'zero byte in first byte of random padding' - this is a mix
    of too long PMS and invalid padding, it actually doesn't send
    padding at all, the padding length is zero
  - 'invalid version number in padding' - this sets the first byte
    of plaintext to 1
  - 'no null separator in encrypted value' - this doesn't send a
    null byte separating padding and encrypted value
  - 'no encrypted value' - this sends a null separator, but it's
    the last byte of plaintext
  - 'too short PKCS padding' - this sends the correct encryption
    type in the padding (2), but one byte later than required
  - 'very short PKCS padding (40 bytes short)' - same as above
    only 40 bytes later
  - 'too long PKCS padding' this doesn't send the PKCS#1 v1.5
    version at all, but starts with padding type
- invalid TLS version in PMS, differences here suggest a leak in
  code checking for correctness of this value:
  - 'wrong TLS version (2, 2) in pre master secret'
  - 'wrong TLS version (0, 0) in pre master secret'
- plaintext with specific Hamming weights, start with 0x00 and 0x02 bytes
  but then switch to special plaintext, differences here suggest a leak
  happening in the maths library:
  - 'very low Hamming weight RSA plaintext' - padding, TLS version and PMS
    are all zero bytes
  - 'very high Hamming weight RSA plaintext' - padding, padding separator, TLS
    version and PMS are all 0xff bytes
  - 'use PKCS#1 padding type 1' - here the padding will be all 0xff bytes
  - 'low Hamming weight RSA plaintext' - padding, padding separator, TLS
    version and PMS are all 0x01 bytes""")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(sampled_tests) + 2 * len(sanity_tests)))
    print("SKIP: {0}".format(len(run_exclude.intersection(conversations.keys()))))
    print("PASS: {0}".format(good))
    print("XFAIL: {0}".format(xfail))
    print("FAIL: {0}".format(bad))
    print("XPASS: {0}".format(xpass))
    print(20 * '=')
    sort = sorted(xpassed, key=natural_sort_keys)
    if len(sort):
        print("XPASSED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))
    sort = sorted(failed, key=natural_sort_keys)
    if len(sort):
        print("FAILED:\n\t{0}".format('\n\t'.join(repr(i) for i in sort)))

    if bad or xpass:
        sys.exit(1)
    elif timing:
        # if regular tests passed, run timing collection and analysis
        if TimingRunner.check_tcpdump():
            timing_runner = TimingRunner("{0}_v{1}_{2}".format(
                                            sys.argv[0],
                                            version,
                                            CipherSuite.ietfNames[cipher]),
                                         sampled_tests,
                                         outdir,
                                         host,
                                         port,
                                         interface,
                                         affinity)
            print("Running timing tests...")
            timing_runner.generate_log(run_only, run_exclude, repetitions)
            ret_val = timing_runner.run()
            if ret_val == 0:
                print("No statistically significant difference detected")
            elif ret_val == 1:
                print("Statisticaly significant difference detected at alpha="
                      "0.05")
            else:
                print("Statistical analysis exited with {0}".format(ret_val))
        else:
            print("Could not run timing tests because tcpdump is not present!")
            sys.exit(1)
        print(20 * '=')


if __name__ == "__main__":
    main()
