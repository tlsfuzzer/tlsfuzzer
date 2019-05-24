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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        CopyVariables
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import RSA_SIG_ALL, key_share_ext_gen

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme
from tlslite.extensions import \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension


"""Script to verify that the DH keys are computed correctly."""


version = 2


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
    print(" --min-zeros num number of zeros that need to be found in the")
    print("                shared secret for the test case to be considered")
    print("                good. 1 by default")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    min_zeros = 1

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:", ["help", "min-zeros="])
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
        elif opt == '--min-zeros':
            min_zeros = int(arg)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    collected_shared_secrets = []
    collected_key_shares = []
    variables_check = \
        {'DH shared secret':
         collected_shared_secrets,
         'ServerHello.extensions.key_share.key_exchange':
         collected_key_shares}

    conversations = {}

    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([TLS_1_3_DRAFT, (3, 3)])
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(CopyVariables(variables_check))
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))

    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(
        AlertGenerator(AlertLevel.warning,
                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    for group in [GroupName.secp384r1, GroupName.secp521r1, GroupName.x25519,
                  GroupName.x448, GroupName.ffdhe2048, GroupName.ffdhe3072]:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [group]
        ext[ExtensionType.key_share] = key_share_ext_gen(groups)
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
            .create([TLS_1_3_DRAFT, (3, 3)])
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256]
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
            .create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(CopyVariables(variables_check))
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\r\n\r\n")))

        # This message is optional and may show up 0 to many times
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        node.next_sibling = ExpectApplicationData()
        node = node.next_sibling.add_child(
            AlertGenerator(AlertLevel.warning,
                           AlertDescription.close_notify))

        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        conversations["TLS 1.3 with {0}".format(GroupName.toStr(group))] \
            = conversation

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
        i = 0
        break_shared = False
        break_key_share = False
        while True:
            # don't hog the memory unnecessairly
            collected_shared_secrets[:] = []
            print("\"{1}\" repeat {0}...".format(i, c_name))
            i += 1
            if c_name == 'sanity':
                break_shared = True
                break_key_share = True

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
                if collected_shared_secrets[-1][:min_zeros] == \
                        bytearray(min_zeros):
                    print("Got shared secret with {0} most significant "
                          "bytes equal to zero."
                          .format(min_zeros))
                    break_shared = True
                # ECDSA key shares have a constant first byte indicating
                # the point encoding
                if "secp" in c_name:
                    if collected_key_shares[-1][:min_zeros+1] == \
                            bytearray(b'\x04') + bytearray(min_zeros):
                        print("Got key share with {0} most significant bytes equal"
                              " to zero.".format(min_zeros))
                        break_key_share = True
                else:
                    if collected_key_shares[-1][:min_zeros] == \
                            bytearray(min_zeros):
                        print("Got key share with {0} most significant bytes equal"
                              " to zero.".format(min_zeros))
                        break_key_share = True
                print("OK\n")
            else:
                bad += 1
                failed.append(c_name)
                break

            if break_shared and break_key_share:
                break

    print('')

    print("Check if the connections work when the calculated DH shared secret")
    print("must be padded on the left with zeros or when the server needs")
    print("to pad its key share")
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
