# Author: Hubert Kario, (c) 2015
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Test if server won't accept forcing SSLv2 ciphers"""
from __future__ import print_function
import traceback
import sys
from random import sample
import getopt

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientMasterKeyGenerator
from tlsfuzzer.expect import ExpectAlert, ExpectClose, ExpectServerHello2, \
        ExpectSSL2Alert

from tlslite.constants import CipherSuite, AlertLevel, \
        ExtensionType, SSL2ErrorDescription

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

    for prot_vers, proto_name in {
            (0, 2):"SSLv2",
            (3, 0):"SSLv3",
            (3, 1):"TLSv1.0"
            }.items():
        for cipher_id, cipher_name in {
                CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5:"DES-CBC3-MD5",
                CipherSuite.SSL_CK_RC4_128_WITH_MD5:"RC4-MD5",
                CipherSuite.SSL_CK_RC4_128_EXPORT40_WITH_MD5:"EXP-RC4-MD5",
                CipherSuite.SSL_CK_RC2_128_CBC_WITH_MD5:"RC2-CBC-MD5",
                CipherSuite.SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5:
                    "EXP-RC2-CBC-MD5",
                CipherSuite.SSL_CK_IDEA_128_CBC_WITH_MD5:"IDEA-CBC-MD5",
                CipherSuite.SSL_CK_DES_64_CBC_WITH_MD5:"DES-CBC-MD5"
                }.items():
            # instruct RecordLayer to use SSLv2 record layer protocol (0, 2)
            conversation = Connect(host, port, version=(0, 2))
            node = conversation
            ciphers = [CipherSuite.SSL_CK_DES_192_EDE3_CBC_WITH_MD5,
                       CipherSuite.SSL_CK_RC4_128_WITH_MD5,
                       CipherSuite.SSL_CK_RC4_128_EXPORT40_WITH_MD5,
                       CipherSuite.SSL_CK_RC2_128_CBC_WITH_MD5,
                       CipherSuite.SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5,
                       CipherSuite.SSL_CK_IDEA_128_CBC_WITH_MD5,
                       CipherSuite.SSL_CK_DES_64_CBC_WITH_MD5]

            node = node.add_child(ClientHelloGenerator(ciphers,
                                                       version=prot_vers,
                                                       ssl2=True))
            # we can get a ServerHello with no ciphers:
            node = node.add_child(ExpectServerHello2())
            # or we can get an error stright away, and connection closure
            node.next_sibling = ExpectSSL2Alert(SSL2ErrorDescription.no_cipher)
            node.next_sibling.add_child(ExpectClose())
            alternative = node.next_sibling
            # or the server may close the connection right away (likely in
            # case SSLv2 is completely disabled)
            alternative.next_sibling = ExpectClose()
            alternative = alternative.next_sibling
            # or finally, we can get a TLS Alert message
            alternative.next_sibling = ExpectAlert()
            alternative.next_sibling.add_child(ExpectClose())
            # in case we got ServerHello, try to force one of the ciphers
            node = node.add_child(ClientMasterKeyGenerator(cipher=cipher_id))
            # it should result in error
            node = node.add_child(ExpectSSL2Alert())
            # or connection close
            node.next_sibling = ExpectClose()
            # in case of error, we expect the server to close connection
            node.add_child(ExpectClose())

            conversations["Connect with {1} {0}"
                          .format(cipher_name, proto_name)] = conversation

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

    print("Note: SSLv2 was officially deprecated (MUST NOT use) in 2011, see")
    print("      RFC 6176.")
    print("      If one or more of the tests fails because of error in form of")
    print("")
    print("      Unexpected message from peer: Handshake()")
    print("")
    print("      With any number inside parethensis, and the server is")
    print("      configured to not support SSLv2, it means it most")
    print("      likely is vulnerable to CVE-2015-3197.")
    print("      In case it's a RC4 or 3DES cipher, you may verify that it")
    print("      really supports it using:")
    print("      test-sslv2-connection.py")
    print("")
    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
