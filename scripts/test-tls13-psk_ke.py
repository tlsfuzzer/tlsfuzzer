# Author: Hubert Kario, (c) 2018
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket, srv_ext_handler_supp_vers, \
        gen_srv_ext_handler_psk

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme, \
        PskKeyExchangeMode
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.utils.compat import a2b_hex, compatAscii2Bytes
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, PskKeyExchangeModesExtension
from tlsfuzzer.helpers import key_share_gen, psk_ext_gen, psk_ext_updater


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
    print(" -n num         only run `num` random tests instead of a full set")
    print("                (excluding \"sanity\" tests)")
    print(" --psk psk      hex encoded (without the 0x) value for the psk")
    print("                secret supported by server")
    print(" --psk-iden identity name associated with the secret configured in")
    print("                server")
    print(" --psk-sha384   use SHA-384 PRF for the PSK (SHA-256 is default)")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    psk_prf = "sha256"
    psk_secret = b'\xaa'
    psk_ident = b'test'

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:",
        ["help", "psk=", "psk-iden=", "psk-sha384"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '--psk':
            psk_secret = a2b_hex(arg)
        elif opt == '--psk-iden':
            psk_ident = compatAscii2Bytes(arg)
        elif opt == '--psk-sha384':
            psk_prf = "sha384"
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ciphers = []
    if psk_prf == "sha256":
        ciphers.append(CipherSuite.TLS_AES_128_GCM_SHA256)
    else:
        ciphers.append(CipherSuite.TLS_AES_256_GCM_SHA384)
    ext = OrderedDict()
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.psk_key_exchange_modes] = PskKeyExchangeModesExtension()\
        .create([PskKeyExchangeMode.psk_ke])
    psk_settings = [(psk_ident, psk_secret, psk_prf)]
    ext[ExtensionType.pre_shared_key] = psk_ext_gen(psk_settings)
    mods = []
    mods.append(psk_ext_updater(psk_settings))
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext,
                                               modifiers=mods))
    ext = {}
    ext[ExtensionType.supported_versions] = srv_ext_handler_supp_vers
    ext[ExtensionType.pre_shared_key] = gen_srv_ext_handler_psk(psk_settings)
    node = node.add_child(ExpectServerHello(extensions=ext))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # run the conversation
    good = 0
    bad = 0
    failed = []
    if not num_limit:
        num_limit = len(conversations)

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throughout
    sanity_tests = [('sanity', conversations['sanity'])]
    regular_tests = [(k, v) for k, v in conversations.items() if k != 'sanity']
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)

    for c_name, c_test in ordered_tests:
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        try:
            runner.run()
        except Exception:
            print("Error while processing")
            print(traceback.format_exc())
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(c_name)

    print("Basic script for psk_ke key exchange in TLS 1.3")
    print("Check if server supports a PSK handshake without use of DHE key")
    print("exchange.")
    print("version: {0}\n".format(version))

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
