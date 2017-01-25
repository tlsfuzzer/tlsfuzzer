# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details

from __future__ import print_function
import traceback
import sys
import getopt
import re
from itertools import chain

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription


def natural_sort_keys(s, _nsre=re.compile('([0-9]+)')):
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(_nsre, s)]


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" --ssl3         expect SSLv3 to be enabled")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    run_exclude = set()
    ssl3 = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:", ["help", "ssl3"])
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
        elif opt == '--ssl3':
            ssl3 = True
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    conversation = Connect(host, port, version=(3, 0))
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
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
    conversations["sanity"] = conversation

    for c_id, name in [(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
                       (0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
                       (0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x000B, "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x000E, "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x0011, "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x0017, "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"),
                       (0x0019, "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"),
                       (0x0026, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"),
                       (0x0027, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"),
                       (0x0028, "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"),
                       (0x0029, "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"),
                       (0x002A, "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"),
                       (0x002B, "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"),
                       (0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"),
                       (0x0063, "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"),
                       (0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"),
                       (0x0065, "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA")]:
        for prot, prot_name in [((3, 3), "TLSv1.2"),
                                ((3, 2), "TLSv1.1"),
                                ((3, 1), "TLSv1.0"),
                                ((3, 0), "SSLv3")]:
            conversation = Connect(host, port, version=(3, 0))
            node = conversation
            ciphers = [c_id,
                       CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            node = node.add_child(ClientHelloGenerator(ciphers, version=prot))
            if prot == (3, 0) and not ssl3:
                node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                                  AlertDescription.protocol_version))
                node = node.add_child(ExpectClose())
            else:
                node = node.add_child(ExpectServerHello(cipher=CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA))
                node = node.add_child(ExpectCertificate())
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
                # allow for 1/n-1 record splitting
                node = node.add_child(ExpectApplicationData())
                record_split = node
                node.next_sibling = ExpectAlert(AlertLevel.warning,
                                              AlertDescription.close_notify)
                node.next_sibling.next_sibling = ExpectClose()
                node = record_split.add_child(record_split.next_sibling)
                node.add_child(ExpectClose())
            conversations["{0} with AES_128 in {1}".format(name, prot_name)] \
                    = conversation

            # alone
            conversation = Connect(host, port, version=(3, 0))
            node = conversation
            ciphers = [c_id,
                       CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
            node = node.add_child(ClientHelloGenerator(ciphers))
            node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                              AlertDescription.handshake_failure))
            node = node.add_child(ExpectClose())
            conversations["{0} in {1}".format(name, prot_name)] = conversation


    # run the conversation
    good = 0
    bad = 0
    failed = []

    # make sure that sanity test is run first and last
    # to verify that server was running and kept running throught
    sanity_test = ('sanity', conversations['sanity'])
    ordered_tests = chain([sanity_test],
                          filter(lambda x: x[0] != 'sanity',
                                 conversations.items()),
                          [sanity_test])

    for c_name, c_test in ordered_tests:
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
            res = False

        if res:
            good += 1
            print("OK\n")
        else:
            bad += 1
            failed.append(c_name)

    print("Test if export grade ciphers are rejected by server. Version 2\n")
    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
