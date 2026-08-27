# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Test if server supports any of the SSLv2 ciphers"""

from __future__ import print_function
from random import sample
import traceback
import sys
import re
import getopt

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        ClientMasterKeyGenerator, Close
from tlsfuzzer.expect import ExpectFinished, ExpectApplicationData, \
        ExpectServerHello2, ExpectVerify

from tlslite.constants import CipherSuite, AlertLevel, \
        ExtensionType
from tlsfuzzer.utils.lists import natural_sort_keys


version = 3


def help_msg():
    """Print usage information"""
    print("Usage: <script-name> [-h hostname] [-p port]")
    print(" -h hostname   hostname to connect to, \"localhost\" by default")
    print(" -p port       port to use for connection, \"4433\" by default")
    print(" -e probe-name  exclude the probe from the list of the ones run")
    print("                may be specified multiple times")
    print(" -n num         run 'num' or all(if 0) tests instead of default(all)")
    print("                (excluding \"sanity\" tests)")
    print(" -x probe-name  expect the probe to fail. When such probe passes despite being marked like this")
    print("                it will be reported in the test summary and the whole script will fail.")
    print("                May be specified multiple times.")
    print(" -X message     expect the `message` substring in exception raised during")
    print("                execution of preceding expected failure probe")
    print("                usage: [-x probe-name] [-X exception], order is compulsory!")
    print(" --help        this message")

def main():
    """Test if the server supports some of the SSLv2 ciphers"""
    conversations = {}
    host = "localhost"
    port = 4433
    num_limit = None
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = None

    argv = sys.argv[1:]

    opts, argv = getopt.getopt(argv, "h:p:e:n:x:X:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-e':
            run_exclude.add(arg)
        elif opt == '-n':
            num_limit = int(arg)
        elif opt == '-x':
            expected_failures[arg] = None
            last_exp_tmp = str(arg)
        elif opt == '-X':
            if not last_exp_tmp:
                raise ValueError("-x has to be specified before -X")
            expected_failures[last_exp_tmp] = str(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))
    if argv:
        help_msg()
        raise ValueError("Unknown options: {0}".format(argv))

    for cipher_id, cipher_name in {
            CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5:"DES-CBC3-MD5",
            CipherSuite.SSL_CK_RC4_128_WITH_MD5:"RC4-MD5",
            CipherSuite.SSL_CK_RC4_128_EXPORT40_WITH_MD5:"EXP-RC4-MD5"
            }.items():
        # instruct RecordLayer to use SSLv2 record layer protocol (0, 2)
        conversation = Connect(host, port, version=(0, 2))
        node = conversation
        ciphers = [CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
                   CipherSuite.SSL_CK_RC4_128_WITH_MD5,
                   CipherSuite.SSL_CK_RC4_128_EXPORT40_WITH_MD5]

        node = node.add_child(ClientHelloGenerator(ciphers,
                                                   version=(0, 2),
                                                   ssl2=True))
        node = node.add_child(ExpectServerHello2())
        node = node.add_child(ClientMasterKeyGenerator(cipher=cipher_id))
        node = node.add_child(FinishedGenerator())  # serves as a CCS
        # ExpectVerify could be be before FinishedGenerator, if the latter
        # didn't serve double duty as a CCS
        node = node.add_child(ExpectVerify())
        node = node.add_child(ExpectFinished(version=(0, 2)))
        node = node.add_child(ApplicationDataGenerator(
            bytearray(b"GET / HTTP/1.0\n\n")))
        node = node.add_child(ExpectApplicationData())
        node.add_child(Close())

        conversations["Connect with SSLv2 {0}"
                      .format(cipher_name)] = conversation

    good = 0
    bad = 0
    xfail = 0
    xpass = 0
    failed = []
    xpassed = []
    shuffled_tests = set(conversations.items())
    if not num_limit:
        num_limit = len(conversations)

    for c_name, conversation in shuffled_tests:
        if c_name in run_exclude:
            continue
        print("{0} ...".format(c_name))

        runner = Runner(conversation)

        res = True
        exception = None
        try:
            runner.run()
        except Exception as exp:
            exception = exp
            print("Error while processing")
            print(traceback.format_exc())
            print("")
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
                good+=1
                print("OK\n")
            else:
                xfail+=1

    print("Note: This test verifies that an implementation implements and")
    print("      will negotiate SSLv2 protocol. This is a BAD configuration.")
    print("      SSLv2 was officially deprecated (MUST NOT use) in 2011, see")
    print("      RFC 6176.")
    print("      It is left here only to verify that the tlslite-ng")
    print("      implementation is correct, so tests for disablement of SSLv2")
    print("      are sane.")
    print("      For same reason, if any of the connections succeeds, the exit")
    print("      code from this script will be 1 (i.e. 'failure')")
    print("")
    print("Test end")
    print(20 * '=')
    print("version: {0}".format(version))
    print(20 * '=')
    print("TOTAL: {0}".format(len(shuffled_tests)))
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

    if good or xpass:
        sys.exit(1)

if __name__ == "__main__":
    main()
