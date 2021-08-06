# Author: Hubert Kario, (c) 2015-2020
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
        ResetHandshakeHashes
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange, ExpectCertificateStatus


from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        GroupName, ExtensionType, PskKeyExchangeMode, ECPointFormat
from tlslite.extensions import SupportedGroupsExtension, \
        SignatureAlgorithmsExtension, SignatureAlgorithmsCertExtension, \
        PskKeyExchangeModesExtension, ECPointFormatsExtension, \
        StatusRequestExtension, ALPNExtension, SupportedVersionsExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.helpers import SIG_ALL, psk_ext_gen, AutoEmptyExtension, \
        key_share_ext_gen, psk_session_ext_gen, psk_ext_updater


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
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (\"sanity\" tests are always executed)")
    print(" -d             negotiate (EC)DHE instead of RSA key exchange")
    print(" --ocsp-enabled Expect the OCSP response from server")
    print(" --help         this message")
    # already used single-letter options:
    # -m test-large-hello.py - min extension number for fuzz testing
    # -s signature algorithms sent by server
    # -k client key
    # -c client certificate
    # -z don't expect 1/n-1 record split in TLS1.0
    # -a override for expected alert description
    # -l override the expected alert level
    # -C explicit cipher for connection
    # -T expected certificates types in CertificateRequest
    # -b server is expected to have multiple (both) certificate types available
    #    at the same time
    # -t timeout to wait for messages (also count of NSTs in
    #    test-tls13-count-tickets.py)
    # -r perform renegotation multiple times
    # -S signature algorithms sent by client
    # -E additional extensions to be sent by client
    #
    # reserved:
    # -x expected fail for probe (alternative to -e)
    # -X expected failure message for probe (to be used together with -x)
    # -i enables timing the test using the specified interface
    # -o output directory for files related to collection of timing information


def main():
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False
    ocsp = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:d", ["help", "ocsp-enabled"])
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
        elif opt == '-d':
            dhe = True
        elif opt == '--ocsp-enabled':
            ocsp = True
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
    if dhe:
        ext = {}
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello(description="first"))
    node = node.add_child(ExpectCertificate())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity"] = conversation

    # sanity renegotiation test case
    conversation = Connect(host, port)
    node = conversation
    ext = OrderedDict()
    # TODO add session_ticket
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(SIG_ALL)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(SIG_ALL)
    groups = [GroupName.secp256r1,
              GroupName.ffdhe2048]
    ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
        .create(groups)
    ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    ext[ExtensionType.key_share] = key_share_ext_gen([GroupName.secp256r1])
    ext[ExtensionType.alpn] = \
        ALPNExtension().create([bytearray(b'http/1.1')])
    ext[ExtensionType.ec_point_formats] = \
        ECPointFormatsExtension().create([
            ECPointFormat.ansiX962_compressed_prime,
            ECPointFormat.ansiX962_compressed_char2,
            ECPointFormat.uncompressed])
    # 18 - signed_certificate_timestamp
    ext[18] = AutoEmptyExtension()
    ext[ExtensionType.status_request] = \
        StatusRequestExtension().create()
    ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
    # yes, don't include TLS 1.3, as we want to be able to renegotiate...
    ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
        .create([(3, 3), (3, 2)])
    ext[ExtensionType.psk_key_exchange_modes] = \
        PskKeyExchangeModesExtension().create(
            [PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
    psk_settings = [(b'test', b'pre-shared key', 'sha256')]
    ext[ExtensionType.pre_shared_key] = psk_ext_gen(psk_settings)
    mods = []
    mods.append(psk_ext_updater(psk_settings))
    if dhe:
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext,
                                               modifiers=mods))
    node = node.add_child(ExpectServerHello(description="first handshake"))
    node = node.add_child(ExpectCertificate())
    if ocsp:
        node = node.add_child(ExpectCertificateStatus())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    renego_exts = OrderedDict(ext)
    # use None for autogeneration of the renegotiation_info with correct
    # payload
    renego_exts[ExtensionType.renegotiation_info] = None
    if ExtensionType.pre_shared_key in renego_exts:
        # make sure the PSK is the last extension
        tmp = renego_exts[ExtensionType.pre_shared_key]
        del renego_exts[ExtensionType.pre_shared_key]
        renego_exts[ExtensionType.pre_shared_key] = tmp
    renego_ciphers = list(ciphers)
    renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
    node = node.add_child(ClientHelloGenerator(
        renego_ciphers,
        extensions=renego_exts,
        session_id=bytearray(0),
        modifiers=mods))
    node = node.add_child(ExpectServerHello(
        description="second handshake"))
    node = node.add_child(ExpectCertificate())
    if ocsp:
        node = node.add_child(ExpectCertificateStatus())
    if dhe:
        node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())

    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["sanity - renegotiation"] = conversation

    # drop specific extensions in the renegotiated client hello
    # signature_algorithms and signature_algorithms_cert are covered
    # by the test-sig-algs-renegotiation-resumption.py
    for drop_ext, exp_result in [
            (ExtensionType.supported_groups, None),
            (ExtensionType.extended_master_secret,
             AlertDescription.handshake_failure),
            (ExtensionType.key_share, None),
            (ExtensionType.alpn, None),
            (ExtensionType.ec_point_formats, None),
            (18, None),  # signed_certificate_timestamp
            (ExtensionType.status_request, None),
            (ExtensionType.post_handshake_auth, None),
            (ExtensionType.supported_versions, None),
            (ExtensionType.psk_key_exchange_modes, None),
            (ExtensionType.pre_shared_key, None)]:
        conversation = Connect(host, port)
        node = conversation
        ext = OrderedDict()
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIG_ALL)
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        ext[ExtensionType.key_share] = key_share_ext_gen([GroupName.secp256r1])
        ext[ExtensionType.alpn] = \
            ALPNExtension().create([bytearray(b'http/1.1')])
        ext[ExtensionType.ec_point_formats] = \
            ECPointFormatsExtension().create([
                ECPointFormat.ansiX962_compressed_prime,
                ECPointFormat.ansiX962_compressed_char2,
                ECPointFormat.uncompressed])
        # 18 - signed_certificate_timestamp
        ext[18] = AutoEmptyExtension()
        ext[ExtensionType.status_request] = \
            StatusRequestExtension().create()
        ext[ExtensionType.post_handshake_auth] = AutoEmptyExtension()
        # yes, don't include TLS 1.3, as we want to be able to renegotiate...
        ext[ExtensionType.supported_versions] = SupportedVersionsExtension()\
            .create([(3, 3), (3, 2)])
        ext[ExtensionType.psk_key_exchange_modes] = \
            PskKeyExchangeModesExtension().create(
                [PskKeyExchangeMode.psk_dhe_ke, PskKeyExchangeMode.psk_ke])
        ext[ExtensionType.pre_shared_key] = psk_ext_gen([
            (b'test', b'pre-shared key')])
        if dhe:
            ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello(description="first handshake"))
        node = node.add_child(ExpectCertificate())
        if ocsp:
            node = node.add_child(ExpectCertificateStatus())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ResetHandshakeHashes())
        renego_exts = OrderedDict(ext)
        del renego_exts[drop_ext]
        # use None for autogeneration of the renegotiation_info with correct
        # payload
        renego_exts[ExtensionType.renegotiation_info] = None
        if ExtensionType.pre_shared_key in renego_exts:
            # make sure the PSK is the last extension
            tmp = renego_exts[ExtensionType.pre_shared_key]
            del renego_exts[ExtensionType.pre_shared_key]
            renego_exts[ExtensionType.pre_shared_key] = tmp
        renego_ciphers = list(ciphers)
        renego_ciphers.remove(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV)
        node = node.add_child(ClientHelloGenerator(
            renego_ciphers,
            extensions=renego_exts,
            session_id=bytearray(0)))
        if exp_result is not None:
            node = node.add_child(ExpectAlert(AlertLevel.fatal, exp_result))
            node.add_child(ExpectClose())
        else:
            node = node.add_child(ExpectServerHello(
                description="second handshake"))
            node = node.add_child(ExpectCertificate())
            if ocsp and drop_ext != ExtensionType.status_request:
                node = node.add_child(ExpectCertificateStatus())
            if dhe:
                node = node.add_child(ExpectServerKeyExchange())
            node = node.add_child(ExpectServerHelloDone())
            node = node.add_child(ClientKeyExchangeGenerator())
            node = node.add_child(ChangeCipherSpecGenerator())
            node = node.add_child(FinishedGenerator())
            node = node.add_child(ExpectChangeCipherSpec())
            node = node.add_child(ExpectFinished())

            node = node.add_child(ApplicationDataGenerator(
                bytearray(b"GET / HTTP/1.0\r\n\r\n")))
            node = node.add_child(ExpectApplicationData())
            node = node.add_child(AlertGenerator(AlertLevel.warning,
                                                 AlertDescription.close_notify))
            node = node.add_child(ExpectAlert())
            node.next_sibling = ExpectClose()
        conversations["drop {0} in renegotiation"
                      .format(ExtensionType.toStr(drop_ext))] = conversation

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

    print("Test how server behaves when the renegotiation Client Hello is")
    print("changed compared to the initial ClientHello.\n")
    print("If the renegotiation is supposed to be disabled use the")
    print("test-renegotiation-disabled.py or")
    print("test-renegotiation-disabled-client-cert.py scripts to verify")
    print("that.\n")

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
