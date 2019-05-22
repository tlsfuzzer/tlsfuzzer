# Author: Stanislav Zidek, (c) 2018
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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        fuzz_message
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectEncryptedExtensions, ExpectCertificateVerify, \
        ExpectNewSessionTicket, ExpectNoMessage

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        TLS_1_3_DRAFT, GroupName, ExtensionType, SignatureScheme
from tlslite.keyexchange import ECDHKeyExchange
from tlsfuzzer.utils.lists import natural_sort_keys
from tlslite.extensions import KeyShareEntry, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.helpers import RSA_SIG_ALL, key_share_ext_gen


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
    print(" -n num         only run `num` random tests instead of a full set")
    print("                (excluding \"sanity\" tests)")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:n:", ["help"])
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
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    # sanity conversation
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
                SignatureScheme.rsa_pss_pss_sha256,
                SignatureScheme.rsa_pss_rsae_sha384,
                SignatureScheme.rsa_pss_pss_sha384]
    ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
        .create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
        .create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
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
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # empty
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_AES_256_GCM_SHA384]
    for cipher in ciphers:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        ext[ExtensionType.key_share] = key_share_ext_gen(groups)
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
            .create([TLS_1_3_DRAFT, (3, 3)])
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.rsa_pss_rsae_sha384,
                    SignatureScheme.rsa_pss_pss_sha384]
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
            .create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(FinishedGenerator(trunc_start=0,
                                                trunc_end=0))

        # This message may be sent right after server finished
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        # we do not expect any application data back
        # after malforming the Finished message
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.decode_error)
        node = node.next_sibling.add_child(ExpectClose())
        conversations["empty - cipher %s" \
                         % (CipherSuite.ietfNames[cipher])] = conversation

    # single bit error
    scenarios = [(CipherSuite.TLS_AES_128_GCM_SHA256, 32),
                 (CipherSuite.TLS_AES_256_GCM_SHA384, 48)]
    for cipher, prf_bytes in scenarios:
        for mbit in range(8*prf_bytes):
            mbyte = mbit // 8 + 1
            conversation = Connect(host, port)
            node = conversation
            ciphers = [cipher,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {}
            groups = [GroupName.secp256r1]
            ext[ExtensionType.key_share] = key_share_ext_gen(groups)
            ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
                .create([TLS_1_3_DRAFT, (3, 3)])
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                        SignatureScheme.rsa_pss_pss_sha256,
                        SignatureScheme.rsa_pss_rsae_sha384,
                        SignatureScheme.rsa_pss_pss_sha384]
            ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
                .create(sig_algs)
            ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
                .create(RSA_SIG_ALL)
            node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
            node = node.add_child(ExpectServerHello())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectEncryptedExtensions())
            node = node.add_child(ExpectCertificate())
            node = node.add_child(ExpectCertificateVerify())
            node = node.add_child(ExpectFinished())
            node = node.add_child(fuzz_message(FinishedGenerator(),
                                               xors={-mbyte: 0x01 << mbit%8}))
            # This message may be sent right after server finished
            cycle = ExpectNewSessionTicket()
            node = node.add_child(cycle)
            node.add_child(cycle)

            # we do not expect any application data back
            # after malforming the Finished message
            node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                            AlertDescription.decrypt_error)
            node = node.next_sibling.add_child(ExpectClose())
            conversations["single bit error - cipher %s, bit %d" \
                          % (CipherSuite.ietfNames[cipher],
                             mbit)] = conversation

    # truncation
    # cipher, start, end
    scenarios = [
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0,  -1),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0,  -2),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0,  -4),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0,  -8),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0,  -16),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0,  -32),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0,  12), # TLS-1.2 size
        (CipherSuite.TLS_AES_128_GCM_SHA256, 1,  None),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 2,  None),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 4,  None),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 8,  None),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 16, None),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 32, None),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0,  -1),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0,  -2),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0,  -4),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0,  -8),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0,  -16), # SHA-256 size
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0,  -32),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0,  12), # TLS-1.2 size
        (CipherSuite.TLS_AES_256_GCM_SHA384, 1,  None),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 2,  None),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 4,  None),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 8,  None),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 16, None), # SHA-256 size
        (CipherSuite.TLS_AES_256_GCM_SHA384, 32, None)
        ]
    for cipher, start, end in scenarios:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [cipher,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        ext[ExtensionType.key_share] = key_share_ext_gen(groups)
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
            .create([TLS_1_3_DRAFT, (3, 3)])
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.rsa_pss_rsae_sha384,
                    SignatureScheme.rsa_pss_pss_sha384]
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
            .create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(FinishedGenerator(trunc_start=start,
                                                trunc_end=end))

        # This message may be sent right after server finished
        cycle = ExpectNewSessionTicket()
        node = node.add_child(cycle)
        node.add_child(cycle)

        # we do not expect any application data back
        # after malforming the Finished message
        node.next_sibling = ExpectAlert(AlertLevel.fatal,
                                        AlertDescription.decode_error)
        node = node.next_sibling.add_child(ExpectClose())
        conversations["truncation - cipher %s, start %d, end %s" \
                      % (CipherSuite.ietfNames[cipher],
                         start, end)] = conversation

    # padding
    # cipher, padding byte, left padding, right padding
    scenarios = [
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 1),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 2),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 4),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 8),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 16), # SHA-384 size
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 32),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 48),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 2**14-4-32), # max record
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 0x20000), # intermediate
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 0x30000), # bigger than max ClientHello
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 0, 256**3-1-32), # max handshake
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 1, 0),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 2, 0),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 4, 0),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 8, 0),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 16, 0), # SHA-384 size
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 32, 0),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 48, 0),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 2**14-4-32, 0), # max record
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 12, 0),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 1, 1),
        (CipherSuite.TLS_AES_128_GCM_SHA256, 0, 8, 8), # SHA-384 size
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 1),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 2),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 4),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 8),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 16), # SHA-512 size
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 32),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 48),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 2**14-4-48), # max record
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 0x20000),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 0x30000), # bigger than max ClientHello
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 256**3-1-48), # max handshake
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 0, 12),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 1, 0),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 2, 0),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 4, 0),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 8, 0),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 16, 0), # SHA-512 size
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 32, 0),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 48, 0),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 2**14-4-48, 0), # max record
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 1, 1),
        (CipherSuite.TLS_AES_256_GCM_SHA384, 0, 8, 8) # SHA-512 size
        ]
    for cipher, pad_byte, pad_left, pad_right in scenarios:
        # longer timeout for longer messages
        # Because the client is sending encrypted data without waiting
        # on any server response, it can actually produce data at a faster
        # rate than the server is able to process it, meaning that a server
        # that aborts only after decrypting a full handshake message may have
        # quite a few records in the queue after we, as a client have finished
        # sending them. Since tlslite-ng has the ciphers implemented in
        # pure python, they are very slow, speeds of just 71.5KiB/s for
        # AES-256-GCM are not atypical. which translates to about 4 minutes
        # to transfer this data. Set the timeout to 5 for a small margin of
        # error.
        # Note: because we still are waiting for the server to send us an alert
        # (all graph terminal nodes go through ExpectAlert), server that fails
        # to do that will still cause the whole test conversation to fail in
        # case it just closes the connection on us
        timeout = 5 if max(pad_left, pad_right) < 2**14 * 4 else 300
        conversation = Connect(host, port, timeout=timeout)
        node = conversation
        ciphers = [cipher,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        ext[ExtensionType.key_share] = key_share_ext_gen(groups)
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
            .create([TLS_1_3_DRAFT, (3, 3)])
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        sig_algs = [SignatureScheme.rsa_pss_rsae_sha256,
                    SignatureScheme.rsa_pss_pss_sha256,
                    SignatureScheme.rsa_pss_rsae_sha384,
                    SignatureScheme.rsa_pss_pss_sha384]
        ext[ExtensionType.signature_algorithms] = SignatureAlgorithmsExtension()\
            .create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = SignatureAlgorithmsCertExtension()\
            .create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())

        # (the crazy handling of the messages below is because we are
        # sending one message (Finished) in multiple records, and server
        # can abort the connection after processing any number of records)

        # conditionally wait for NewSessionTicket messages
        # this will help in case the server does send early NST (without
        # waiting for client Finished) but will abort reading of the
        # Finished after one record
        no_message = node.add_child(ExpectNoMessage(0.001))
        nst = ExpectNewSessionTicket(note='first')
        no_message.next_sibling = nst
        nst.add_child(no_message)
        node = no_message

        # alert+close can happen during sending large Finished message,
        # therefore we are specifying it as its sibling
        close_node = ExpectAlert(AlertLevel.fatal,
                                 AlertDescription.decode_error)
        close_node.add_child(ExpectClose())
        node = node.add_child(FinishedGenerator(
                                  pad_byte=pad_byte,
                                  pad_left=pad_left,
                                  pad_right=pad_right))
        node.next_sibling = close_node

        # This message may be sent right after server finished
        cycle = ExpectNewSessionTicket(note='second')
        node = node.add_child(cycle)
        node.add_child(cycle)

        # we do not expect any application data back
        # after malforming the Finished message
        node.next_sibling = close_node

        conversations["padding - cipher %s, "
                      "pad_byte %d, "
                      "pad_left %d, "
                      "pad_right %d" \
                      % (CipherSuite.ietfNames[cipher],
                         pad_byte, pad_left, pad_right)] = conversation

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

    print("Fuzzing TLS 1.3 Finished messages")
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
