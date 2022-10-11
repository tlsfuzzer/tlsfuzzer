# Author: Alexander Sosedkin, (c) 2022
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
        FinishedGenerator, ApplicationDataGenerator, \
        CertificateGenerator, CertificateVerifyGenerator, \
        AlertGenerator, CompressedCertificateGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest, \
        ExpectApplicationData, ExpectEncryptedExtensions, \
        ExpectCertificateVerify, ExpectNewSessionTicket, \
        ExpectCompressedCertificate, \
        gen_cln_ext_handler_compress_certificate, \
        clnt_ext_handler_status_request, \
        clnt_ext_handler_sig_algs
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import key_share_ext_gen, RSA_SIG_ALL, \
        expected_ext_parser, dict_update_non_present
from tlslite.extensions import SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension, ClientKeyShareExtension, \
        SupportedVersionsExtension, SupportedGroupsExtension, \
        CompressCertificateExtension
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        HashAlgorithm, SignatureAlgorithm, ExtensionType, SignatureScheme, \
        GroupName, CertificateCompressionAlgorithm, CertificateType
from tlslite.messages import CompressedCertificate
from tlslite.utils.compression import *
from tlslite.utils import tlshashlib
from tlslite.utils.cryptomath import numBytes
from tlslite.utils.keyfactory import parsePEMKey
from tlslite.x509 import X509
from tlslite.x509certchain import X509CertChain


version = 1


def expected_ext_parser_cr(names):
    # _ext_name_to_id is private, so we're using a public API backwards
    return expected_ext_parser(' '.join((x + ':CR' for x in names.split(' '))))


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname              name of the host to run the test against")
    print("                          localhost by default")
    print(" -p port                  port number to use for connection")
    print("                          4433 by default")
    print(" probe-name               if present, will run only the probes")
    print("                          with given names and not all of them,")
    print("                          e.g \"sanity\"")
    print(" -e probe-name            exclude the probe from the list")
    print("                          of the ones run,")
    print("                          may be specified multiple times")
    print(" -x probe-name            expect the probe to fail. When such probe")
    print("                          passes despite being marked like this")
    print("                          it will be reported in the test summary")
    print("                          and the whole script will fail.")
    print("                          May be specified multiple times.")
    print(" -X message               expect the `message` substring ")
    print("                          in exception raised during execution of")
    print("                          preceding expected failure probe")
    print("                          usage: [-x probe-name] [-X exception],")
    print("                          order is compulsory!")
    print(" -n num                   run 'num' or all(if 0) tests")
    print("                          instead of default(all)")
    print("                          (\"sanity\" tests are always executed)")
    print(" -k keyfile               file with private key of client")
    print(" -c certfile              file with the certificate of client")
    print(" --algorithms algorithms  comma-separated list of compression")
    print("                          algorithms: zlib,brotli,zstd")
    print(" -E ext_spec              List of the extensions expected in")
    print("                          server's CertificateRequest")
    print("                          besides compress_certificate(27).")
    print("                          The ids can be specified")
    print("                          by name (\"status_request\"")
    print("                          or by number (\"5\").")
    print("                          IDs must be separated by spaces.")
    print(" --help                   this message")


def main():
    """Check client certificate compression"""
    hostname = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    cert = None
    private_key = None
    compression_algorithms_list = ['zlib', 'brotli', 'zstd']
    ext_spec = None

    # algorithms to advertise in ClientHello
    sig_algs = [SignatureScheme.rsa_pkcs1_sha256,
                (HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
                SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha256]

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:k:c:a:E:",
                               ["algorithms=", "help"])
    for opt, arg in opts:
        if opt == '-h':
            hostname = arg
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
        elif opt == '--algorithms':
            compression_algorithms_list = arg.split(',')
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        elif opt == '-k':
            text_key = open(arg, 'rb').read()
            if sys.version_info[0] >= 3:
                text_key = str(text_key, 'utf-8')
            private_key = parsePEMKey(text_key, private=True)
        elif opt == '-c':
            text_cert = open(arg, 'rb').read()
            if sys.version_info[0] >= 3:
                text_cert = str(text_cert, 'utf-8')
            cert = X509()
            cert.parse(text_cert)
        elif opt == '-E':
            ext_spec = arg
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    for alg_name in compression_algorithms_list:
        if alg_name not in ('zlib', 'brotli', 'zstd'):
            raise RuntimeError("unsupported algorithm `{0}`".format(alg_name))
    if 'brotli' in compression_algorithms_list and not brotliLoaded:
        raise RuntimeError('unsupported algorithm `brotli`, '
                           'install Brotli python bindings '
                           'or disable brotli testing with `-a`')
    if 'zstd' in compression_algorithms_list and not zstdLoaded:
        raise RuntimeError('unsupported algorithm `zstd`, install zstd python '
                           'bindings or disable zstd testing with `-a`')

    compression_algorithms = {}
    if 'zlib' in compression_algorithms_list:
        compression_algorithms['zlib'] = CertificateCompressionAlgorithm.zlib
    if 'brotli' in compression_algorithms_list:
        compression_algorithms['brotli'] = \
                CertificateCompressionAlgorithm.brotli
    if 'zstd' in compression_algorithms_list:
        compression_algorithms['zstd'] = CertificateCompressionAlgorithm.zstd

    cr_expected_ext = {}
    if ext_spec is not None:
        ext_spec = expected_ext_parser_cr(ext_spec)
        cr_expected_ext = dict_update_non_present(cr_expected_ext,
                                                  ext_spec['CR'])


    if not cert or not private_key:
        raise Exception("A Client certificate and a private key are required")

    certType = cert.certAlg

    conversations = {}


    # "sanity"
    # no certificate compression involved, just check for Client Certificates
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = \
        SupportedVersionsExtension().create([(3, 4)])
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificateRequest())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(CertificateVerifyGenerator(private_key))
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")
    ))
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


    # "server ignores compress_certificate"
    # check that server doesn't compress certificate when suggested
    conversation = Connect(hostname, port)
    node = conversation
    ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    ext = {}
    groups = [GroupName.secp256r1]
    ext[ExtensionType.key_share] = key_share_ext_gen(groups)
    ext[ExtensionType.supported_versions] = \
        SupportedVersionsExtension().create([(3, 4)])
    ext[ExtensionType.supported_groups] = \
        SupportedGroupsExtension().create(groups)
    ext[ExtensionType.signature_algorithms] = \
        SignatureAlgorithmsExtension().create(sig_algs)
    ext[ExtensionType.signature_algorithms_cert] = \
        SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
    ext[ExtensionType.compress_certificate] = \
            CompressCertificateExtension().create([
                CertificateCompressionAlgorithm.zlib
            ])
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectEncryptedExtensions())
    node = node.add_child(ExpectCertificateRequest(extensions=cr_expected_ext))
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateVerify())
    node = node.add_child(ExpectFinished())
    node = node.add_child(CertificateGenerator(X509CertChain([cert])))
    node = node.add_child(CertificateVerifyGenerator(private_key))
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ApplicationDataGenerator(
        bytearray(b"GET / HTTP/1.0\r\n\r\n")
    ))
    # This message is optional and may show up 0 to many times
    cycle = ExpectNewSessionTicket()
    node = node.add_child(cycle)
    node.add_child(cycle)

    node.next_sibling = ExpectApplicationData()
    node = node.next_sibling.add_child(AlertGenerator(AlertLevel.warning,
                                       AlertDescription.close_notify))

    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    conversations["server ignores compress_certificate"] = conversation


    # "{}-compressed certificate aborts"
    # check that server rejects an unsolicited compressed certificate
    for alg_name, algorithm in compression_algorithms.items():
        conversation = Connect(hostname, port)
        node = conversation
        ciphers = [CipherSuite.TLS_AES_128_GCM_SHA256,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        ext = {}
        groups = [GroupName.secp256r1]
        ext[ExtensionType.key_share] = key_share_ext_gen(groups)
        ext[ExtensionType.supported_versions] = \
            SupportedVersionsExtension().create([(3, 4)])
        ext[ExtensionType.supported_groups] = \
            SupportedGroupsExtension().create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(sig_algs)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectEncryptedExtensions())
        node = node.add_child(ExpectCertificateRequest(extensions=cr_expected_ext))
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateVerify())
        node = node.add_child(ExpectFinished())
        node = node.add_child(CompressedCertificateGenerator(
            X509CertChain([cert]),
            algorithm=algorithm
        ))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.unexpected_message))
        node.next_sibling = ExpectClose()
        conversations["{0}-compressed certificate aborts".format(alg_name)] = \
                conversation


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
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
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

    print("Test to verify server support for client certificate compression.")

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
