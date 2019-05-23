# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Test if server supports any of the SSLv2 ciphers"""

from __future__ import print_function
from random import sample
import traceback
import sys
import getopt

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        FinishedGenerator, ApplicationDataGenerator, \
        ClientMasterKeyGenerator, Close
from tlsfuzzer.expect import ExpectFinished, ExpectApplicationData, \
        ExpectServerHello2, ExpectVerify

from tlslite.constants import CipherSuite, AlertLevel, \
        ExtensionType

def help_msg():
    """Print usage information"""
    print("Usage: <script-name> [-h hostname] [-p port]")
    print(" -h hostname   hostname to connect to, \"localhost\" by default")
    print(" -p port       port to use for connection, \"4433\" by default")
    print(" --help        this message")

def main():
    """Test if the server supports some of the SSLv2 ciphers"""
    conversations = {}
    host = "localhost"
    port = 4433

    argv = sys.argv[1:]

    opts, argv = getopt.getopt(argv, "h:p:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            host = arg
        elif opt == '-p':
            port = int(arg)
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

    shuffled_tests = sample(list(conversations.items()), len(conversations))

    for conversation_name, conversation in shuffled_tests:
        print("{0} ...".format(conversation_name))

        runner = Runner(conversation)

        res = True
        try:
            runner.run()
        except:
            print("Error while processing")
            print(traceback.format_exc())
            print("")
            res = False

        if res:
            good+=1
            print("OK\n")
        else:
            bad+=1

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
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if good > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
