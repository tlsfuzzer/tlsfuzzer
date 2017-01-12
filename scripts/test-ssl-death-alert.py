# CVE-2016-8610
# SSL Death Alert
# OpenSSL SSL/TLS SSL3_AL_WARNING undefined alert flood remote DoS

from __future__ import print_function
import traceback
import sys
import getopt

from tlsfuzzer.runner import Runner
from tlsfuzzer.messages import Connect, ClientHelloGenerator, \
        ClientKeyExchangeGenerator, ChangeCipherSpecGenerator, \
        FinishedGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectClose
from tlslite.constants import CipherSuite, AlertLevel, AlertDescription


def help_msg():
    print("Usage: <script-name> [-h hostname] [-p port] [-n number_of_alerts]")
    print(" -h hostname          name of the host to run the test against")
    print("                      localhost by default")
    print(" -p port              port number to use for connection,")
    print("                      4433 by default")
    print(" -n number_of_alerts  how many alerts client sends to server,")
    print("                      4 by default")
    print(" --help               this message")


def main():
    hostname = "localhost"
    port = 4433
    number_of_alerts = 4

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:n:", ["help"])
    for opt, arg in opts:
        if opt == '-h':
            hostname = arg
        elif opt == '-p':
            port = int(arg)
        elif opt == '-n':
            number_of_alerts = int(arg)
        elif opt == '--help':
            help_msg()
            sys.exit(0)
        else:
            raise ValueError("Unknown option: {0}".format(opt))

    conversations = {}

    conversation = Connect(hostname, port, version=(3, 3))
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers))
    for _ in range(number_of_alerts):  # sending alerts during handshake
        node = node.add_child(AlertGenerator(  # alert description: 46, 41, 43
            AlertLevel.warning, AlertDescription.unsupported_certificate))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ClientKeyExchangeGenerator())
    node = node.add_child(ChangeCipherSpecGenerator())
    node = node.add_child(FinishedGenerator())
    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(AlertGenerator(
        AlertLevel.warning, AlertDescription.close_notify))
    node = node.add_child(ExpectAlert(AlertLevel.warning,
                                      AlertDescription.close_notify))
    node.next_sibling = ExpectClose()
    conversations["SSL Death Alert without getting alert"] = conversation

    conversation = Connect(hostname, port, version=(3, 3))
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA]
    node = node.add_child(ClientHelloGenerator(ciphers))
    for _ in range(number_of_alerts+1):
        node = node.add_child(AlertGenerator(
            AlertLevel.warning, AlertDescription.unsupported_certificate))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(ExpectCertificate())
    node = node.add_child(ExpectServerHelloDone())
    node = node.add_child(ExpectAlert(AlertLevel.fatal))
    node = node.add_child(ExpectClose())
    conversations["SSL Death Alert with getting alert"] = conversation


    good = 0
    bad = 0

    for conversation_name, conversation in conversations.items():
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
            good += 1
            print("OK\n")
        else:
            bad += 1

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
