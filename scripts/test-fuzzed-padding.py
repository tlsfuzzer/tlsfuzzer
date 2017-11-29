# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Example MAC value fuzzer"""

from __future__ import print_function
import traceback
import sys
import getopt

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        fuzz_padding, CertificateGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose, ExpectCertificateRequest

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [[probe-name] ...]")
    print(" -h hostname    name of the host to run the test against")
    print("                localhost by default")
    print(" -p port        port number to use for connection, 4433 by default")
    print(" probe-name     if present, will run only the probes with given")
    print("                names and not all of them, e.g \"sanity\"")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" --help         this message")


def main():
    """check if incorrect padding is rejected by server"""
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:", ["help"])
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
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    if args:
        run_only = set(args)
    else:
        run_only = None

    conversations = {}

    for pos, val in [
                     (-1, 0x01),
                     (-1, 0xff),
                     (-2, 0x01),
                     (-2, 0xff),
                     (-6, 0x01),
                     (-6, 0xff),
                     (-12, 0x01),
                     (-12, 0xff),
                     (-20, 0x01),
                     (-20, 0xff),
                     # we're generating at least 20 bytes of padding
                     ]:
        conversation = Connect(host, port)
        node = conversation
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
        node = node.add_child(ClientHelloGenerator(ciphers))
        node = node.add_child(ExpectServerHello())
        node = node.add_child(ExpectCertificate())
        node = node.add_child(ExpectCertificateRequest())
        fork = node
        node = node.add_child(ExpectServerHelloDone())
        node = node.add_child(CertificateGenerator())

        # handle servers which ask for client certificates
        fork.next_sibling = ExpectServerHelloDone()
        join = ClientKeyExchangeGenerator()
        fork.next_sibling.add_child(join)

        node = node.add_child(join)
        node = node.add_child(ChangeCipherSpecGenerator())
        node = node.add_child(FinishedGenerator())
        node = node.add_child(ExpectChangeCipherSpec())
        node = node.add_child(ExpectFinished())
        node = node.add_child(fuzz_padding(ApplicationDataGenerator(
                                                        b"GET / HTTP/1.0\n\n"),
                                           xors={pos:val},
                                           min_length=20))
        node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                          AlertDescription.bad_record_mac))
#        node.next_sibling = ExpectClose()
        node = node.add_child(ExpectClose())

        conversations["XOR position " + str(pos) + " with " + str(hex(val))] = \
                conversation

    # zero-fill the padding
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectCertificateRequest())
    fork = node
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(CertificateGenerator())

    # handle servers which ask for client certificates
    fork.next_sibling = ExpectServerHelloDone()
    join = ClientKeyExchangeGenerator()
    fork.next_sibling.add_child(join)

    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    # block size for AES-128 is 16 bytes
    # SHA-1 MAC is 20 bytes long
    # length of "GET / HTTP" is 10 bytes
    # which means the padding will be two bytes - 1 byte of padding and one
    # byte length
    node = node.add_child(fuzz_padding(ApplicationDataGenerator(
                                                    b"GET / HTTP"),
                                       substitutions={0:0}))
    node = node.add_child(ExpectAlert(AlertLevel.fatal,
                                      AlertDescription.bad_record_mac))
#   node.next_sibling = ExpectClose()
    node = node.add_child(ExpectClose())

    conversations["zero-filled"] = \
            conversation

    # run the conversation
    good = 0
    bad = 0

    for c_name, c_test in conversations.items():
        if run_only and c_name not in run_only or c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(c_test)

        res = True
        #because we don't want to abort the testing and we are reporting
        #the errors to the user, using a bare except is OK
        #pylint: disable=bare-except
        try:
            runner.run()
        except:
            print("Error while processing")
            print(traceback.format_exc())
            res = False
        #pylint: enable=bare-except

        if res:
            good+=1
            print("OK")
        else:
            bad+=1

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
