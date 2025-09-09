# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain
from random import sample

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator, \
        split_message, FlushMessageList
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName, HashAlgorithm, SignatureAlgorithm, SignatureScheme
from tlslite.extensions import PaddingExtension, TLSExtension, \
        SupportedGroupsExtension, SignatureAlgorithmsExtension, \
        SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.lists import natural_sort_keys
from tlsfuzzer.helpers import AutoEmptyExtension

version = 5


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname                     name of the host to run the test against")
    print("                                 localhost by default")
    print(" -p port                         port number to use for connection, 4433 by default")
    print(" probe-name                      if present, will run only the probes with given")
    print("                                 names and not all of them, e.g \"sanity\"")
    print(" -e probe-name                   exclude the probe from the list of the ones run")
    print("                                 may be specified multiple times")
    print(" -x probe-name                   expect the probe to fail. When such probe passes despite being marked like this")
    print("                                 it will be reported in the test summary and the whole script will fail.")
    print("                                 May be specified multiple times.")
    print(" -X message                      expect the `message` substring in exception raised during")
    print("                                 execution of preceding expected failure probe")
    print("                                 usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" -n num                          run 'num' or all(if 0) tests instead of default(50)")
    print("                                 (excluding \"sanity\" tests)")
    print(" -d                              negotiate (EC)DHE instead of RSA key exchange")
    print(" -m min-ext-no                   the minimum extension number to use (default=52)")
    print("                                 (the test uses random extensions past this number)")
    print(" --shorten-huge-hello-by amount  shorten the 'Huge hello' test by amount number of bytes (default=0)")
    print(" -M | --ems                      enable support for Extended Master Secret")
    print(" --help                          this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = 50
    min_ext = 52
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None
    dhe = False
    huge_hello_reduction = 0
    ems = False
    SIGS = [(getattr(HashAlgorithm, x), SignatureAlgorithm.rsa) for x in
               ['sha512', 'sha256']] + [
                   SignatureScheme.rsa_pss_rsae_sha256,
                   SignatureScheme.rsa_pss_rsae_sha512,
                   SignatureScheme.rsa_pss_pss_sha256,
                   SignatureScheme.rsa_pss_pss_sha512]

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:m:dM", ["help", "shorten-huge-hello-by=", "ems"])
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
        elif opt == '-m':
            min_ext = int(arg)
        elif opt == '--shorten-huge-hello-by':
            if arg[:2] == '0x':
                huge_hello_reduction = int(arg, 16)
            else:
                huge_hello_reduction = int(arg)
        elif opt == '-M' or opt == '--ems':
            ems = True
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
    ext = {}
    if dhe:
        groups = [GroupName.secp256r1,
                  GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIGS)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIGS)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                   CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if not ext:
        ext = None
    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
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
        bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["sanity"] = conversation

    # send client hello with large padding extension
    final_size = 0xffff - (50 if dhe else 4) - (4 if ems else 0)
    for i in chain(range(10), range(0x3f00, 0x4010), range(0x1ff0, 0x2010),
                   range(0x8ff0, 0x9010), range(0xff00, final_size)):
        conversation = Connect(host, port)
        node = conversation
        if dhe:
            ext = {}
            groups = [GroupName.secp256r1,
                    GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIGS)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIGS)
            ext[ExtensionType.client_hello_padding] = PaddingExtension().create(i)
            ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {ExtensionType.client_hello_padding:PaddingExtension().create(i)}
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())
        conversations["ext padding, {0} bytes".format(i)] = conversation

    # send large extension from unallocated range
    final_size = 0xffff - (50 if dhe else 4) - (4 if ems else 0)
    for i in chain(range(10), range(0x3f00, 0x4010), range(0x1ff0, 0x2010),
                   range(0x8ff0, 0x9010), range(0xff00, final_size)):
        conversation = Connect(host, port)
        node = conversation
        if dhe:
            ext = {}
            groups = [GroupName.secp256r1,
                    GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIGS)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIGS)
            ext[80] = TLSExtension(extType=80).create(bytearray(i))
            ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {80:TLSExtension(extType=80).create(bytearray(i))}
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())
        conversations["ext #80, {0} bytes".format(i)] = conversation

    # send two extensions, where one is large (4096) and the other is
    # changing size
    final_size = 0xefff - 8 - (50 if dhe else 0) - (4 if ems else 0)
    for i in chain(range(10), range(0x2f00, 0x3010),
                   range(0x3f00, 0x4010), range(0x1ff0, 0x2010),
                   range(0x8ff0, 0x9010), range(0xef00, final_size)):
        conversation = Connect(host, port)
        node = conversation
        if dhe:
            ext = {}
            groups = [GroupName.secp256r1,
                    GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIGS)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIGS)
            ext[80] = TLSExtension(extType=80).create(bytearray(i))
            ext[ExtensionType.client_hello_padding] = PaddingExtension().create(0x1000)
            ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {80:TLSExtension(extType=80).create(bytearray(i)),
                ExtensionType.client_hello_padding:
                   PaddingExtension().create(0x1000)}
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())
        conversations["two ext, #80 {0} bytes".format(i)] = conversation

    # send client hello messages with multiple extensions
    final_size = 0x10000//4 - (11 if dhe else 0) - (4 if ems else 0)
    for i in chain(range(10//4), range(0x3f00//4, 0x4010//4),
                   range(0x1ff0//4, 0x2010//4),
                   range(0x8ff0//4, 0x9010//4), range(0xff00//4, final_size)):
        conversation = Connect(host, port)
        node = conversation
        if dhe:
            high_num_ext = (ExtensionType.supports_npn,
                            ExtensionType.tack,
                            ExtensionType.renegotiation_info)
            for num in high_num_ext:
                if i+min_ext > num:
                    i+=1
            ext = dict((j, TLSExtension(extType=j))
                        for j in range(min_ext, min_ext+i)
                        if j not in high_num_ext)
            groups = [GroupName.secp256r1,
                    GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIGS)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIGS)
            ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            high_num_ext = (ExtensionType.supports_npn,
                            ExtensionType.tack,
                            ExtensionType.renegotiation_info)
            # increase the count if some extension points will be skipped because
            # they are meaningful
            for num in high_num_ext:
                if i+min_ext > num:
                    i+=1
            ext = dict((j, TLSExtension(extType=j))
                        for j in range(min_ext, min_ext+i)
                        if j not in high_num_ext)
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())
        conversations["multiple extensions {0}".format(i)] = conversation

    # send client hello with large number of ciphersuites but overall
    # even length
    final_size = 0xffff//2-2 if not dhe else  0xffff//2-3
    for i in chain(range(1, 10//2), range(0x3f00//2, 0x4010//2),
                   range(0x1ff0//2, 0x2010//2),
                   range(0x8ff0//2, 0x9010//2), range(0xff00//2, final_size)):
        conversation = Connect(host, port)
        node = conversation
        if i < 0x5600 - 0x0100:
            ciphers = list(range(0x0100, 0x0100 + i))
        else:
            ciphers = list(range(0x0100, 0x5600))
            i -= 0x5600 - 0x0100
            ciphers += list(range(0x5601, 0x5601 + i))
        if dhe:
            ext = {}
            groups = [GroupName.secp256r1,
                        GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIGS)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIGS)
            ciphers += [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ext = {}
            ciphers += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        if not ext:
            ext = None
        node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())
        conversations["ciphers even {0}".format(i)] = conversation

    # send client hello with large number of ciphersuites but overall
    # odd length
    final_size = 0xffff//2-2 if not dhe else  0xffff//2-3
    for i in chain(range(1, 10//2), range(0x3f00//2, 0x4010//2),
                   range(0x1ff0//2, 0x2010//2),
                   range(0x8ff0//2, 0x9010//2), range(0xff00//2, final_size)):
        conversation = Connect(host, port)
        node = conversation
        if i < 0x5600 - 0x0100:
            ciphers = list(range(0x0100, 0x0100 + i))
        else:
            ciphers = list(range(0x0100, 0x5600))
            i -= 0x5600 - 0x0100
            ciphers += list(range(0x5601, 0x5601 + i))
        if dhe:
            ext = {}
            groups = [GroupName.secp256r1,
                    GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIGS)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIGS)
            ext[ExtensionType.client_hello_padding] = PaddingExtension().create(1)
            ciphers += [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ext = {ExtensionType.client_hello_padding:
                    PaddingExtension().create(1)}
            ciphers += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   extensions=ext))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())
        conversations["ciphers odd {0}".format(i)] = conversation

    # hello split over at least two records, first very small (2B)
    final_size = 0xffff - (50 if dhe else 4) - (4 if ems else 0)
    for i in chain(range(10), range(0x3f00, 0x4010), range(0x1ff0, 0x2010),
                   range(0x8ff0, 0x9010), range(0xff00, final_size)):
        fragment_list = []
        conversation = Connect(host, port)
        node = conversation
        if dhe:
            ext = {}
            groups = [GroupName.secp256r1,
                    GroupName.ffdhe2048]
            ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
                .create(groups)
            ext[ExtensionType.signature_algorithms] = \
                SignatureAlgorithmsExtension().create(SIGS)
            ext[ExtensionType.signature_algorithms_cert] = \
                SignatureAlgorithmsCertExtension().create(SIGS)
            ext[ExtensionType.client_hello_padding] = PaddingExtension().create(i)
            ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        else:
            ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            ext = {ExtensionType.client_hello_padding:PaddingExtension().create(i)}
        if ems:
            ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        hello_gen = ClientHelloGenerator(ciphers, extensions=ext)
        node = node.add_child(split_message(hello_gen, fragment_list, 2))
        node = node.add_child(FlushMessageList(fragment_list))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        if dhe:
            node = node.add_child(ExpectServerKeyExchange())
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(ClientKeyExchangeGenerator())
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node = node.add_child(AlertGenerator(AlertLevel.warning,
                                             AlertDescription.close_notify))
        node = node.add_child(ExpectAlert())
        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())
        conversations["fragmented, padding ext {0} bytes".format(i)] = conversation

    # sanity check fragmentation
    fragment_list = []
    conversation = Connect(host, port)
    node = conversation
    ext = {}
    if dhe:
        groups = [GroupName.secp256r1,
                GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIGS)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIGS)
        ciphers = [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
    if not ext:
        ext = None
    hello_gen = ClientHelloGenerator(ciphers, extensions=ext)
    node = node.add_child(split_message(hello_gen, fragment_list, 2))
    node = node.add_child(FlushMessageList(fragment_list))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
            node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["sanity check - fragmented"] = conversation

    # test with ciphers and extensions filled to the brim
    conversation = Connect(host, port)
    node = conversation
    i = 0xfffe // 2 - 2 if not dhe else 0xfffe // 2 - 4 # two ciphers are constant or four with ECDHE key
    if i < 0x5600 - 0x0100:
        ciphers = list(range(0x0100, 0x0100 + i))
    else:
        ciphers = list(range(0x0100, 0x5600))
        i -= 0x5600 - 0x0100
        ciphers += list(range(0x5601, 0x5601 + i))
    ext = {}
    huge_hello_len = 0xffff - huge_hello_reduction
    if dhe:
        groups = [GroupName.secp256r1,
                GroupName.ffdhe2048]
        ext[ExtensionType.supported_groups] = SupportedGroupsExtension()\
            .create(groups)
        ext[ExtensionType.signature_algorithms] = \
            SignatureAlgorithmsExtension().create(SIGS)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(SIGS)
        ciphers += [CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        huge_hello_len -= 50
    else:
        ciphers += [CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
                    CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
        # the 4 bytes subtracted from 0xffff are for ext ID and ext len
        huge_hello_len -= 4
    if ems:
        ext[ExtensionType.extended_master_secret] = AutoEmptyExtension()
        huge_hello_len -= 4
    ext[80] = TLSExtension(extType=80).create(bytearray(huge_hello_len))

    node = node.add_child(ClientHelloGenerator(ciphers, extensions=ext))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    if dhe:
            node = node.add_child(ExpectServerKeyExchange())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ApplicationDataGenerator(bytearray(b"GET / HTTP/1.0\n\n")))
    node = node.add_child(ExpectApplicationData())
    node = node.add_child(AlertGenerator(AlertLevel.warning,
                                         AlertDescription.close_notify))
    node = node.add_child(ExpectAlert())
    node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())
    conversations["huge hello"] = conversation

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
    run_sanity = True
    if run_only:
        if len(run_only) == 1 and 'sanity' in run_only:
            run_sanity = False
            regular_tests = sanity_tests
        else:
            if not 'sanity' in run_only:
                run_sanity = False
            regular_tests = [(k, v) for k, v in conversations.items() if
                             k in run_only and (k != 'sanity')]
    else:
        regular_tests = [(k, v) for k, v in conversations.items() if
                         (k != 'sanity') and k not in run_exclude]
    sampled_tests = sample(regular_tests, min(num_limit, len(regular_tests)))
    if run_sanity:
        ordered_tests = chain(sanity_tests, sampled_tests, sanity_tests)
    else:
        ordered_tests = sampled_tests

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
    if run_sanity:
        print("TOTAL: {0}".format(len(sampled_tests) + 2 * len(sanity_tests)))
    else:
        print("TOTAL: {0}".format(len(sampled_tests)))
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
