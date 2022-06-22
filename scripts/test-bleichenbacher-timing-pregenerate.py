# Author: Jan Koscielniak, (c) 2020
# Author: Hubert Kario, (c) 2020-2022
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Bleichenbacher attack reproducer with timing side-channel check"""
from __future__ import print_function
import traceback
import sys
import getopt
import os
from itertools import chain, repeat
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
from tlsfuzzer.utils.statics import WARM_UP
from tlsfuzzer.utils.log import Log


version = 1


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
    print(" --test-set     Execute a pre-selected subset of tests.")
    print("                Available: 'raw decrypted value'")
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
    test_set = None

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv,
                               "h:p:e:x:X:t:n:a:l:l:o:i:C:",
                               ["help",
                                "no-safe-renego",
                                "no-sni",
                                "repeat=",
                                "cpu-list=",
                                "static-enc",
                                "test-set="])
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
        elif opt == "--test-set":
            test_set = arg
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    if run_only and test_set:
        raise ValueError("Can't specify test set and individual tests together")

    if test_set == "raw decrypted value":
        if reuse_rsa_ciphertext:
            run_only = set((
                "control - fuzzed pre master secret 1",
                "control - fuzzed pre master secret 2",
                "control - fuzzed pre master secret 3",
                "too short PKCS padding - 1 bytes - 0",
                "too short PKCS padding - 1 bytes - 1",
                "too short PKCS padding - 1 bytes - 2",
                "too short PKCS padding - 1 bytes - 3",
                "too short PKCS padding - 4 bytes - 0",
                "too short PKCS padding - 4 bytes - 1",
                "too short PKCS padding - 4 bytes - 2",
                "too short PKCS padding - 4 bytes - 3",
                "too short PKCS padding - 8 bytes - 0",
                "too short PKCS padding - 8 bytes - 1",
                "too short PKCS padding - 8 bytes - 2",
                "too short PKCS padding - 8 bytes - 3",
                "very short PKCS padding (40 bytes short) - 0",
                "very short PKCS padding (40 bytes short) - 1",
                "very short PKCS padding (40 bytes short) - 2",
                "very short PKCS padding (40 bytes short) - 3",
            ))
        else:
            run_only = set((
                "control - fuzzed pre master secret 1",
                "control - fuzzed pre master secret 2",
                "control - fuzzed pre master secret 3",
                "too short PKCS padding - 1 bytes",
                "too short PKCS padding - 4 bytes",
                "too short PKCS padding - 8 bytes",
                "very short PKCS padding (40 bytes short)",
            ))
    elif test_set is not None:
        raise ValueError("Unrecognised test set name: {0}".format(test_set))

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
    generators = OrderedDict()

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
        server_cert_state = runner.state
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

    for i in range(1, 4):
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
        padding_xors=None
        if i == 3:
            # for the third control probe make sure that the signal from
            # fuzzing is very visible to the server
            padding_xors=dict((i, 0) for i in range(120))
        node = node.add_child(ClientKeyExchangeGenerator(
            padding_subs={-3: 0, -2: 3, -1: 3},
            padding_xors=padding_xors,
            premaster_secret=bytearray([0] * 46),
            reuse_encrypted_premaster=reuse_rsa_ciphertext))
        cke_node = node
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        conversations["control - fuzzed pre master secret {0}".format(i)] =\
            conversation
        generators["control - fuzzed pre master secret {0}".format(i)] = \
            cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["set PKCS#1 padding type to 3"] = conversation
    generators["set PKCS#1 padding type to 3"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["set PKCS#1 padding type to 1"] = conversation
    generators["set PKCS#1 padding type to 1"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["use PKCS#1 padding type 1"] = conversation
    generators["use PKCS#1 padding type 1"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["zero byte in random padding"] = conversation
    generators["zero byte in random padding"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["zero byte in last byte of random padding"] = conversation
    generators["zero byte in last byte of random padding"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["zero byte in first byte of random padding"] = conversation
    generators["zero byte in first byte of random padding"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["invalid version number in padding"] = conversation
    generators["invalid version number in padding"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["no null separator in padding"] = conversation
    generators["no null separator in padding"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["no null separator in encrypted value"] = conversation
    generators["no null separator in encrypted value"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["random plaintext"] = conversation
    generators["random plaintext"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["two byte long PMS (TLS version only)"] = conversation
    generators["two byte long PMS (TLS version only)"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["no encrypted value"] = conversation
    generators["no encrypted value"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["one byte encrypted value"] = conversation
    generators["one byte encrypted value"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["too short (47-byte) pre master secret"] = conversation
    generators["too short (47-byte) pre master secret"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very short (4-byte) pre master secret"] = conversation
    generators["very short (4-byte) pre master secret"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["too long (49-byte) pre master secret"] = conversation
    generators["too long (49-byte) pre master secret"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very long (124-byte) pre master secret"] = conversation
    generators["very long (124-byte) pre master secret"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very long (96-byte) pre master secret"] = conversation
    generators["very long (96-byte) pre master secret"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["wrong TLS version (2, 2) in pre master secret"] = conversation
    generators["wrong TLS version (2, 2) in pre master secret"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["wrong TLS version (0, 0) in pre master secret"] = conversation
    generators["wrong TLS version (0, 0) in pre master secret"] = cke_node

    for rep in range(4 if reuse_rsa_ciphertext else 1):
        for i in [1, 4, 8]:
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
            padding_subs = {}
            for j in range(1, 1+i):
                padding_subs[j] = 0
            padding_subs[i+1] = 2
            node = node.add_child(ClientKeyExchangeGenerator(
                padding_subs=padding_subs,
                reuse_encrypted_premaster=reuse_rsa_ciphertext))
            cke_node = node
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(TCPBufferingDisable())
            node = node.add_child(TCPBufferingFlush())
            node = node.add_child(ExpectAlert(level,
                                              alert))
            node.add_child(ExpectClose())

            suffix = ""
            if reuse_rsa_ciphertext:
                suffix = " - {0}".format(rep)

            conversations["too short PKCS padding - {0} bytes{1}"
                .format(i, suffix)] = conversation
            generators["too short PKCS padding - {0} bytes{1}"
                .format(i, suffix)] = cke_node

    for j in range(4 if reuse_rsa_ciphertext else 1):
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
        cke_node = node
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(TCPBufferingDisable())
        node = node.add_child(TCPBufferingFlush())
        node = node.add_child(ExpectAlert(level,
                                          alert))
        node.add_child(ExpectClose())

        suffix = ""
        if reuse_rsa_ciphertext:
            suffix = " - {0}".format(j)

        conversations["very short PKCS padding (40 bytes short){0}"
            .format(suffix)] = conversation
        generators["very short PKCS padding (40 bytes short){0}"
            .format(suffix)] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["too long PKCS padding"] = conversation
    generators["too long PKCS padding"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very low Hamming weight RSA plaintext"] = conversation
    generators["very low Hamming weight RSA plaintext"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["low Hamming weight RSA plaintext"] = conversation
    generators["low Hamming weight RSA plaintext"] = cke_node

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
    cke_node = node
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(TCPBufferingDisable())
    node = node.add_child(TCPBufferingFlush())
    node = node.add_child(ExpectAlert(level,
                                      alert))
    node.add_child(ExpectClose())

    conversations["very high Hamming weight RSA plaintext"] = conversation
    generators["very high Hamming weight RSA plaintext"] = cke_node

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
  - 'control - fuzzed pre master secret 1',
    'control - fuzzed pre master secret 2', and
    'control - fuzzed pre master secret 3' - this will end up with random
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
  - 'too short PKCS padding - 1 bytes', 'too short PKCS padding - 4 bytes',
    'too short PKCS padding - 8 bytes' - this sends the correct encryption
    type in the padding (2), but one, 4 or 8 bytes later than required
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
            tests = [('generic', None)]

            timing_runner = TimingRunner("{0}_v{1}_{2}".format(
                                            sys.argv[0],
                                            version,
                                            CipherSuite.ietfNames[cipher]),
                                         tests,
                                         outdir,
                                         host,
                                         port,
                                         interface,
                                         affinity,
                                         skip_extract=True)
            print("Pre-generating pre-master secret values...")

            with open(
                os.path.join(timing_runner.out_dir, 'pms_values.bin'),
                "wb"
            ) as pms_file:
                # create a real order of tests to run
                log = Log(os.path.join(timing_runner.out_dir, "real_log.csv"))
                actual_tests = []
                node_dict = {}
                for c_name, c_test in sampled_tests:
                    if run_only and c_name not in run_only or \
                            c_name in run_exclude:
                        continue
                    if not c_name.startswith("sanity"):
                        actual_tests.append(c_name)
                        node_dict[c_name] = generators[c_name]

                log.start_log(actual_tests)
                for _ in range(repetitions):
                    log.shuffle_new_run()
                log.write()
                log.read_log()
                test_classes = log.get_classes()
                queries = chain(repeat(0, WARM_UP), log.iterate_log())

                exp_key_size = \
                    (len(server_cert_state.get_server_public_key()) + 7) // 8

                # generate the PMS values
                for executed, index in enumerate(queries):
                    g_name = test_classes[index]
                    g_node = node_dict[g_name]

                    res = g_node.generate(server_cert_state)
                    assert len(res.encryptedPreMasterSecret) == exp_key_size, \
                        len(res.encryptedPreMasterSecret)

                    pms_file.write(res.encryptedPreMasterSecret)


            # fake the set of tests to run so it's just one
            pms_file = open(
                os.path.join(timing_runner.out_dir, 'pms_values.bin'),
                "rb"
            )

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
                encrypted_premaster_file=pms_file,
                encrypted_premaster_length=exp_key_size
                ))
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(TCPBufferingDisable())
            node = node.add_child(TCPBufferingFlush())
            node = node.add_child(ExpectAlert(level,
                                              alert))
            node.add_child(ExpectClose())

            tests[:] = [('generic', conversation)]

            print("Running timing tests...")
            timing_runner.generate_log(
                ['generic'], [],
                repetitions * len(sampled_tests))
            ret_val = timing_runner.run()
            if ret_val != 0:
                print("run failed")
                sys.exit(ret_val)
            os.remove(os.path.join(timing_runner.out_dir, 'log.csv'))
            os.rename(
                os.path.join(timing_runner.out_dir, 'real_log.csv'),
                os.path.join(timing_runner.out_dir, 'log.csv')
            )
            if not timing_runner.extract():
                ret_val = 2
            else:
                timing_runner.analyse()

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
