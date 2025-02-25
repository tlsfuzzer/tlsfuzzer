# Author: Hubert Kario, (c) 2017
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Verify that different iOS clients can connect to the server under test."""

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
        FinishedGenerator, ApplicationDataGenerator, AlertGenerator
from tlsfuzzer.expect import ExpectServerHello, ExpectCertificate, \
        ExpectServerHelloDone, ExpectChangeCipherSpec, ExpectFinished, \
        ExpectAlert, ExpectApplicationData, ExpectClose, \
        ExpectServerKeyExchange
from tlslite.extensions import SNIExtension, ECPointFormatsExtension, \
        SupportedGroupsExtension, SignatureAlgorithmsExtension, NPNExtension, \
        TLSExtension, ClientKeyShareExtension, KeyShareEntry, \
        SupportedVersionsExtension, SignatureAlgorithmsCertExtension
from tlsfuzzer.utils.ordered_dict import OrderedDict

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName, ECPointFormat, HashAlgorithm, \
        SignatureAlgorithm
from tlsfuzzer.helpers import RSA_SIG_ALL
from tlsfuzzer.utils.lists import natural_sort_keys


version = 5


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
    print(" -n num         run 'num' or all(if 0) tests instead of default(50)")
    print("                (excluding \"sanity\" tests)")
    print(" -d             Use (EC)DHE instead of RSA for key exchange (for")
    print("                sanity probes only)")
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
    num_limit = 50
    run_exclude = set()
    expected_failures = {}
    last_exp_tmp = str()
    dhe = False

    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "h:p:e:x:X:n:d", ["help"])
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
            SignatureAlgorithmsExtension().create(RSA_SIG_ALL)
        ext[ExtensionType.signature_algorithms_cert] = \
            SignatureAlgorithmsCertExtension().create(RSA_SIG_ALL)
        ciphers = [CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    else:
        ext = None
        ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                   CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
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
    conversations["sanity"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [4,
        5,
        47,
        51,
        50,
        10,
        22,
        19,
        9,
        21,
        18,
        3,
        8,
        20,
        17,
        255]
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0]))
    node = node.add_child(ExpectServerHello())
    conversations["56: Android 2.3.7 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49172,
        49162,
        57,
        56,
        49167,
        49157,
        53,
        49170,
        49160,
        22,
        19,
        49165,
        49155,
        10,
        49171,
        49161,
        51,
        50,
        49166,
        49156,
        47,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08\x00\t\x00\n\x00\x0b\x00\x0c\x00\r\x00\x0e\x00\x0f\x00\x10\x00\x11\x00\x12\x00\x13\x00\x14\x00\x15\x00\x16\x00\x17\x00\x18\x00\x19'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[1, 0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["58: Android 4.0.4 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49172,
        49162,
        49186,
        49185,
        57,
        56,
        49167,
        49157,
        53,
        49170,
        49160,
        49180,
        49179,
        22,
        19,
        49165,
        49155,
        10,
        49171,
        49161,
        49183,
        49182,
        51,
        50,
        49166,
        49156,
        47,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[1, 0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["59: Android 4.1.1 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49172,
        49162,
        49186,
        49185,
        57,
        56,
        49167,
        49157,
        53,
        49170,
        49160,
        49180,
        49179,
        22,
        19,
        49165,
        49155,
        10,
        49171,
        49161,
        49183,
        49182,
        51,
        50,
        49166,
        49156,
        47,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["60: Android 4.2.2 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49172,
        49162,
        49186,
        49185,
        57,
        56,
        49167,
        49157,
        53,
        49170,
        49160,
        49180,
        49179,
        22,
        19,
        49165,
        49155,
        10,
        49171,
        49161,
        49183,
        49182,
        51,
        50,
        49166,
        49156,
        47,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["61: Android 4.3 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49200,
        49196,
        49172,
        49162,
        163,
        159,
        107,
        106,
        57,
        56,
        157,
        61,
        53,
        49170,
        49160,
        22,
        19,
        10,
        49199,
        49195,
        49191,
        49187,
        49171,
        49161,
        162,
        158,
        103,
        64,
        51,
        50,
        156,
        60,
        47,
        49169,
        49159,
        5,
        4,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x19\x00\x18\x00\x17'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00 \x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x01\x01'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["62: Android 4.4.2 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [52244,
        52243,
        52245,
        49172,
        49162,
        57,
        56,
        53,
        49170,
        49160,
        22,
        19,
        10,
        49199,
        49195,
        49171,
        49161,
        162,
        158,
        51,
        50,
        156,
        47,
        49169,
        49159,
        5,
        4,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00 \x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x01\x01'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x19\x00\x18\x00\x17'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["88: Android 5.0.0 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [52244,
        52243,
        52245,
        49195,
        49199,
        158,
        49162,
        49172,
        57,
        49161,
        49171,
        51,
        156,
        53,
        47,
        10,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x12\x08http/1.1\x08spdy/3.1'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["129: Android 6.0 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [52393,
        52392,
        52244,
        52243,
        49195,
        49199,
        49196,
        49200,
        49161,
        49171,
        49162,
        49172,
        156,
        157,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x1d\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["139: Android 7.0 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [255,
        49196,
        49195,
        49188,
        49162,
        49187,
        49161,
        49200,
        49199,
        49192,
        49191,
        49171]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x0c\x05\x01\x04\x01\x02\x01\x05\x03\x04\x03\x02\x03'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00.\x02h2\x05h2-16\x05h2-15\x05h2-14\x08spdy/3.1\x06spdy/3\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["112: Apple ATS 9 on iOS 9"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        4,
        5,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["94: Baidu Jan 2015 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [47,
        53,
        5,
        10,
        49171,
        49172,
        49161,
        49162,
        50,
        56,
        19,
        4]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["41: BingBot Dec 2013 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [57,
        56,
        53,
        22,
        19,
        10,
        51,
        50,
        47,
        7,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[1, 0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["47: BingPreview Dec 2013 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49200,
        49196,
        49192,
        49188,
        49172,
        49162,
        49186,
        49185,
        163,
        159,
        107,
        106,
        57,
        56,
        136,
        135,
        49202,
        49198,
        49194,
        49190,
        49167,
        49157,
        157,
        61,
        53,
        132,
        49170,
        49160,
        49180,
        49179,
        22,
        19,
        49165,
        49155,
        10,
        49199,
        49195,
        49191,
        49187,
        49171,
        49161,
        49183,
        49182,
        162,
        158,
        103,
        64,
        51,
        50,
        154,
        153,
        69,
        68,
        49201,
        49197,
        49193,
        49189,
        49166,
        49156,
        156,
        60,
        47,
        150,
        65,
        7,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00 \x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x01\x01'))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[1, 0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["91: BingPreview Jan 2015 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [57,
        56,
        53,
        22,
        19,
        10,
        51,
        50,
        47,
        7,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[1, 0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["74: BingPreview Jun 2014 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        102,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        5,
        4,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[30031] = TLSExtension(extType=30031).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 2), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["10: Chrome 27 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        102,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        5,
        4,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[30031] = TLSExtension(extType=30031).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 2), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["11: Chrome 28 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49162,
        49172,
        57,
        107,
        53,
        61,
        49159,
        49161,
        49187,
        49169,
        49171,
        49191,
        51,
        103,
        50,
        5,
        4,
        47,
        60,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[30031] = TLSExtension(extType=30031).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 2), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["12: Chrome 29 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49162,
        49172,
        57,
        107,
        53,
        61,
        49159,
        49161,
        49187,
        49169,
        49171,
        49191,
        51,
        103,
        50,
        5,
        4,
        47,
        60,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00 \x06spdy/2\x06spdy/3\x08spdy/3.1\x08http/1.1'))
    ext[30031] = TLSExtension(extType=30031).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["38: Chrome 30 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        158,
        156,
        49162,
        49172,
        57,
        53,
        49159,
        49161,
        49169,
        49171,
        51,
        50,
        5,
        4,
        47,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00 \x06spdy/2\x06spdy/3\x08spdy/3.1\x08http/1.1'))
    ext[30031] = TLSExtension(extType=30031).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["46: Chrome 31 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        158,
        156,
        49162,
        49172,
        57,
        53,
        49159,
        49161,
        49169,
        49171,
        51,
        50,
        5,
        4,
        47,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00 \x06spdy/2\x06spdy/3\x08spdy/3.1\x08http/1.1'))
    ext[30031] = TLSExtension(extType=30031).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["49: Chrome 32 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [52244,
        52243,
        49195,
        49199,
        158,
        156,
        49162,
        49172,
        57,
        53,
        49159,
        49161,
        49169,
        49171,
        51,
        50,
        5,
        4,
        47,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x19\x06spdy/3\x08spdy/3.1\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["54: Chrome 33 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        158,
        52244,
        52243,
        49162,
        49161,
        49171,
        49172,
        49159,
        49169,
        51,
        50,
        57,
        156,
        47,
        53,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x19\x06spdy/3\x08spdy/3.1\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["66: Chrome 34 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [52244,
        52243,
        49195,
        49199,
        158,
        49162,
        49161,
        49171,
        49172,
        49159,
        49169,
        51,
        50,
        57,
        156,
        47,
        53,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x19\x06spdy/3\x08spdy/3.1\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["69: Chrome 35 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [52244,
        52243,
        49195,
        49199,
        158,
        49162,
        49161,
        49171,
        49172,
        49159,
        49169,
        51,
        50,
        57,
        156,
        47,
        53,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x19\x06spdy/3\x08spdy/3.1\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["76: Chrome 36 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        158,
        52244,
        52243,
        49162,
        49161,
        49171,
        49172,
        49159,
        49169,
        51,
        50,
        57,
        156,
        47,
        53,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x19\x06spdy/3\x08spdy/3.1\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["80: Chrome 37 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49199,
        49195,
        158,
        52244,
        52243,
        52245,
        49172,
        49162,
        57,
        49171,
        49161,
        51,
        49169,
        49159,
        156,
        53,
        47,
        5,
        4,
        10,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x19\x08http/1.1\x06spdy/3\x08spdy/3.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["82: Chrome 39 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49199,
        49195,
        158,
        52244,
        52243,
        52245,
        49172,
        49162,
        57,
        49171,
        49161,
        51,
        49169,
        49159,
        156,
        53,
        47,
        5,
        4,
        10,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x12\x08http/1.1\x08spdy/3.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["89: Chrome 40 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        158,
        52244,
        52243,
        52245,
        49162,
        49172,
        57,
        49161,
        49171,
        51,
        49159,
        49169,
        156,
        53,
        47,
        5,
        4,
        10,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x18\x08http/1.1\x08spdy/3.1\x05h2-14'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["105: Chrome 42 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        158,
        52244,
        52243,
        52245,
        49162,
        49172,
        57,
        49161,
        49171,
        51,
        156,
        53,
        47,
        10,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x1b\x08http/1.1\x08spdy/3.1\x05h2-14\x02h2'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["108: Chrome 43 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        158,
        52244,
        52243,
        52245,
        49162,
        49172,
        57,
        49161,
        49171,
        51,
        156,
        53,
        47,
        10,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x1b\x08http/1.1\x08spdy/3.1\x05h2-14\x02h2'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["115: Chrome 45 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        158,
        52244,
        52243,
        49162,
        49172,
        57,
        49161,
        49171,
        51,
        156,
        53,
        47,
        10]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x08http/1.1\x08spdy/3.1\x02h2'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["117: Chrome 47 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        158,
        52244,
        52243,
        49162,
        49172,
        57,
        49161,
        49171,
        51,
        156,
        53,
        47,
        10]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["122: Chrome 48 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        52393,
        52392,
        52244,
        52243,
        49162,
        49172,
        49161,
        49171,
        156,
        53,
        47,
        10]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["124: Chrome 49 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49199,
        52392,
        52243,
        49172,
        49171,
        156,
        53,
        47,
        10]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x03\x01\x03\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["136: Chrome 49 on XP SP3"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        52393,
        52392,
        52244,
        52243,
        49162,
        49172,
        49161,
        49171,
        156,
        53,
        47,
        10]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x1d\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["125: Chrome 50 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49196,
        49200,
        52393,
        52392,
        52244,
        52243,
        49161,
        49171,
        49162,
        49172,
        156,
        157,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x06\x01\x06\x03\x05\x01\x05\x03\x04\x01\x04\x03\x02\x01\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x1d\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["126: Chrome 51 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [14906,
        4865,
        4866,
        4867,
        49195,
        49199,
        49196,
        49200,
        52393,
        52392,
        49171,
        49172,
        156,
        157,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[14906] = TLSExtension(extType=14906).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[40] = TLSExtension(extType=40).create(bytearray(b'\x00)\n\n\x00\x01\x00\x00\x1d\x00 \xbe\xb5^\xc1\x7f\xeeSqV\tX\xf7\x8d\xb4\x9dM\xc37#\xe4* \x0b$dkmw\xa7\xa9Hg'))
    ext[45] = TLSExtension(extType=45).create(bytearray(b'\x01\x01'))
    ext[43] = SupportedVersionsExtension().create([(170, 170), (127, 18), (3, 3), (3, 2), (3, 1)])
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x08\n\n\x00\x1d\x00\x17\x00\x18'))
    ext[56026] = TLSExtension(extType=56026).create(bytearray(b'\x00'))
    ext[21] = TLSExtension(extType=21).create(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["141: Chrome 57 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [43690,
        4865,
        4866,
        4867,
        49195,
        49199,
        49196,
        49200,
        52393,
        52392,
        49171,
        49172,
        156,
        157,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[47802] = TLSExtension(extType=47802).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[30032] = TLSExtension(extType=30032).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[51] = ClientKeyShareExtension().create([KeyShareEntry().create(64250, bytearray(b'\x00'), None), KeyShareEntry().create(29, bytearray(b"\xbf\xd1V\x04p-\xb7\xf4\xb6\x93\xd3F\xe3--=\xfc\x8d\xff$81\x0f\x00.\xefy\xd1\xd8\x8a\xc9\'"), bytearray(b'\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05'))])
    ext[45] = TLSExtension(extType=45).create(bytearray(b'\x01\x01'))
    ext[43] = SupportedVersionsExtension().create([(122, 122), (127, 23), (3, 3), (3, 2), (3, 1)])
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x08\xfa\xfa\x00\x1d\x00\x17\x00\x18'))
    ext[23130] = TLSExtension(extType=23130).create(bytearray(b'\x00'))
    ext[21] = TLSExtension(extType=21).create(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["149: Chrome 65 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [51914,
        4865,
        4866,
        4867,
        49195,
        49199,
        49196,
        49200,
        52393,
        52392,
        49171,
        49172,
        156,
        157,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[60138] = TLSExtension(extType=60138).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[51] = ClientKeyShareExtension().create([KeyShareEntry().create(64250, bytearray(b'\x00'), None), KeyShareEntry().create(29, bytearray(b'\xa1$\n\xaf!\x0btR\xe6\xed\x11\xb1j \xa6\x8c*O\xeb\\\x87\x06\x86\xa3.\xeb\x8f\xf1t G\x0c'), bytearray(b'\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05'))])
    ext[45] = TLSExtension(extType=45).create(bytearray(b'\x01\x01'))
    ext[43] = SupportedVersionsExtension().create([(250, 250), (127, 28), (3, 3), (3, 2), (3, 1)])
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x08\xfa\xfa\x00\x1d\x00\x17\x00\x18'))
    ext[39578] = TLSExtension(extType=39578).create(bytearray(b'\x00'))
    ext[21] = TLSExtension(extType=21).create(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["152: Chrome 69 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49200,
        49199,
        49192,
        49191,
        49172,
        49171,
        159,
        158,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02\x06\x01\x06\x03'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["110: Edge 12 on Win 10"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49196,
        49195,
        49200,
        49199,
        159,
        158,
        49188,
        49187,
        49192,
        49191,
        49162,
        49161,
        49172,
        49171,
        157,
        156,
        61,
        60,
        53,
        47,
        10,
        106,
        64,
        56,
        50,
        19]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02\x06\x01\x06\x03'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[21760] = TLSExtension(extType=21760).create(bytearray(b'\x00\x01\x00\x02\x00\x02'))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["119: Edge 13 on Win 10"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49196,
        49195,
        49200,
        49199,
        159,
        158,
        49188,
        49187,
        49192,
        49191,
        49162,
        49161,
        49172,
        49171,
        57,
        51,
        157,
        156,
        61,
        60,
        53,
        47,
        10,
        106,
        64,
        56,
        50,
        19]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02\x06\x01\x06\x03'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[21760] = TLSExtension(extType=21760).create(bytearray(b'\x00\x01\x00\x02\x00\x02'))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["130: Edge 13 on Win 10"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49196,
        49195,
        49200,
        49199,
        159,
        158,
        49188,
        49187,
        49192,
        49191,
        49162,
        49161,
        49172,
        49171,
        157,
        156,
        61,
        60,
        53,
        47,
        10,
        106,
        64,
        56,
        50,
        19]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02\x06\x01\x06\x03'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[21760] = TLSExtension(extType=21760).create(bytearray(b'\x00\x01\x00\x02\x00\x02'))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["120: Edge 13 on Win Phone 10"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49196,
        49195,
        49200,
        49199,
        49188,
        49187,
        49192,
        49191,
        49162,
        49161,
        49172,
        49171,
        157,
        156,
        61,
        60,
        53,
        47,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x1d\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02\x06\x01\x06\x03'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[24] = TLSExtension(extType=24).create(bytearray(b'\x00\n\x03\x02\x01\x00'))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["144: Edge 15 on Win 10"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        5,
        4,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["14: Firefox 10.0.12 ESR on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        5,
        4,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["15: Firefox 17.0.7 ESR on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        136,
        135,
        57,
        56,
        132,
        53,
        69,
        68,
        51,
        50,
        150,
        65,
        5,
        4,
        47,
        22,
        19,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08\x00\t\x00\n\x00\x0b\x00\x0c\x00\r\x00\x0e\x00\x0f\x00\x10\x00\x11\x00\x12\x00\x13\x00\x14\x00\x15\x00\x16\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["16: Firefox 21 on Fedora 19"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        5,
        4,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["13: Firefox 21 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        5,
        4,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["17: Firefox 22 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        5,
        4,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["37: Firefox 24 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49161,
        49159,
        49171,
        49169,
        69,
        68,
        51,
        50,
        49166,
        49164,
        49156,
        49154,
        150,
        65,
        47,
        5,
        4,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["48: Firefox 24.2.0 ESR on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49161,
        49159,
        49171,
        49169,
        69,
        68,
        51,
        50,
        49166,
        49164,
        49156,
        49154,
        150,
        65,
        47,
        5,
        4,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["50: Firefox 26 on Win 8"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        49170,
        49159,
        49169,
        51,
        50,
        69,
        57,
        56,
        136,
        22,
        47,
        65,
        53,
        132,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["51: Firefox 27 on Win 8"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        49170,
        49159,
        49169,
        51,
        50,
        69,
        57,
        56,
        136,
        22,
        47,
        65,
        53,
        132,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["67: Firefox 29 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        49170,
        49159,
        49169,
        51,
        50,
        69,
        57,
        56,
        136,
        22,
        47,
        65,
        53,
        132,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["70: Firefox 30 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        49170,
        49159,
        49169,
        51,
        50,
        69,
        57,
        56,
        136,
        22,
        47,
        65,
        53,
        132,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["77: Firefox 31 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        49170,
        49159,
        49169,
        51,
        50,
        69,
        57,
        56,
        136,
        22,
        47,
        65,
        53,
        132,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["84: Firefox 31.3.0 ESR on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        49170,
        49159,
        49169,
        51,
        50,
        69,
        57,
        56,
        136,
        22,
        47,
        65,
        53,
        132,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["79: Firefox 32 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        49159,
        49169,
        51,
        50,
        57,
        47,
        53,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x19\x08spdy/3.1\x06spdy/3\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["83: Firefox 34 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        49159,
        49169,
        51,
        50,
        57,
        47,
        53,
        10,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x1f\x05h2-14\x08spdy/3.1\x06spdy/3\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["90: Firefox 35 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b"\x00\'\x05h2-16\x05h2-15\x05h2-14\x02h2\x08spdy/3.1\x08http/1.1"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["103: Firefox 37 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b"\x00\'\x05h2-16\x05h2-15\x05h2-14\x02h2\x08spdy/3.1\x08http/1.1"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["109: Firefox 39 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["116: Firefox 41 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["118: Firefox 42 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["123: Firefox 44 on OS X"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["127: Firefox 45 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["128: Firefox 46 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        52393,
        52392,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["132: Firefox 47 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        52393,
        52392,
        49196,
        49200,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x16\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x05\x02\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["135: Firefox 49 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        52393,
        52392,
        49196,
        49200,
        49162,
        49161,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x15\x02h2\x08spdy/3.1\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x16\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x05\x02\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["137: Firefox 49 on XP SP3"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [4865,
        4867,
        4866,
        49195,
        49199,
        52393,
        52392,
        49196,
        49200,
        49171,
        49172,
        51,
        57,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[21] = TLSExtension(extType=21).create(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[40] = TLSExtension(extType=40).create(bytearray(b"\x00i\x00\x1d\x00 \xab i\xb8\xbe\x8c\xdd\x01\x8b\xca\x89\x86\x9fb\xbf\xbc\xc0\xe2@\xb2\x8c\xcc(\xf9\xc3J\x0cl=\'\xb3C\x00\x17\x00A\x04\x1a\xbf\x1bt\xec\xef\xdc\xb4f\xe1\x97\xa7\xbeG\xfb\xbd\xbfLm\x10\xe8\xb9\xb7=\xf2\x12v\xa2\xdf\xc4\x03\xdbm\xb3\x07\xb3\x94FS\x00\xde!k*;\xa4}\x87\xce\x88:\xdfe\xea\xe1\xe2\xa0\xad\xb8!\xe0\xa6J\x06"))
    ext[43] = SupportedVersionsExtension().create([(127, 18), (3, 3), (3, 2), (3, 1)])
    ext[65283] = TLSExtension(extType=65283).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01'))
    ext[45] = TLSExtension(extType=45).create(bytearray(b'\x01\x01'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["142: Firefox 53 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [4865,
        4867,
        4866,
        49195,
        49199,
        52393,
        52392,
        49196,
        49200,
        49171,
        49172,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[51] = ClientKeyShareExtension().create([KeyShareEntry().create(29, bytearray(b'\x16\xafM\xe5\x96a\xc2\xd9>c\xfb\xc4\x13O\x07\xf5eA^\xc6\xc8k3\xb2\xa2\x05\xe9\xa5\x16\xbe\x1e"'), bytearray(b'\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05')), KeyShareEntry().create(23, bytearray(b'\x04\xf0<\xda,\xf1\x93{\x84\x112#l\x89)j\xcd#\x1b9\x0cHM\x03\x81J\xb5\xcb3v\x0c`\x03jPUn\x1f\x18FaT\x14\x7fA\xd4\xa1J\xce\xa7U+\xaeS:\xa8\xcfrbhf\xfa\xfdN\x0c'), 5)])
    ext[43] = SupportedVersionsExtension().create([(127, 23), (3, 3), (3, 2), (3, 1)])
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01'))
    ext[45] = TLSExtension(extType=45).create(bytearray(b'\x01\x01'))
    ext[21] = TLSExtension(extType=21).create(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["150: Firefox 59 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [4865,
        4867,
        4866,
        49195,
        49199,
        52393,
        52392,
        49196,
        49200,
        49171,
        49172,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x0c\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[51] = ClientKeyShareExtension().create([KeyShareEntry().create(29, bytearray(b'3\xdeW\x93\x89|0\x80\xf1\xcep\xff\xbe\x88/\xbe~\x15t\\W\x89\xa4\x004\xafT\xf2@e\x89\t'), bytearray(b'\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05\x05')), KeyShareEntry().create(23, bytearray(b'\x04\xf9z0\xc4\x17\xdczu\xf7R\x92\x87<2\xbc\xac\xb0(\xdc\x90H\xfc\xde\x11\x91x0a\x1b\xd1|\x83O\xfb\x1d\x14\x8e\xb7\x14h\x81\xcc0\xaf;\xd7"\xea\xf5\x9dQ\xd9\xf1\x93\xe4\xc8\x88W\x9e\x82\x85\xcaF\xe7'), 5)])
    ext[43] = SupportedVersionsExtension().create([(127, 28), (3, 3), (3, 2), (3, 1)])
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x16\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05\x01\x06\x01\x02\x03\x02\x01'))
    ext[45] = TLSExtension(extType=45).create(bytearray(b'\x01\x01'))
    ext[21] = TLSExtension(extType=21).create(bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["151: Firefox 62 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        49159,
        49169,
        49161,
        49171,
        49162,
        49172,
        156,
        5,
        4,
        47,
        10,
        53,
        51,
        50,
        22,
        19,
        57,
        56,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["97: Googlebot Feb 2015 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49195,
        49199,
        52393,
        52392,
        49196,
        49200,
        49161,
        49171,
        49162,
        49172,
        156,
        157,
        47,
        53,
        10]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x1d\x00\x17\x00\x18'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["145: Googlebot Feb 2018 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49159,
        49169,
        49161,
        49171,
        49162,
        49172,
        5,
        4,
        47,
        10,
        53,
        51,
        50,
        22,
        19,
        57,
        56,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["72: Googlebot Jun 2014 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49159,
        49169,
        49161,
        49171,
        49162,
        49172,
        5,
        4,
        47,
        10,
        53,
        51,
        50,
        22,
        19,
        57,
        56,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["40: Googlebot Oct 2013 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [47,
        53,
        5,
        10,
        49171,
        49172,
        49161,
        49162,
        50,
        56,
        19,
        4]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["64: IE 10 on Win Phone 8.0"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49200,
        49199,
        49192,
        49191,
        49172,
        49171,
        159,
        158,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02\x06\x01\x06\x03'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["107: IE 11 on Win 10"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49196,
        49195,
        49200,
        49199,
        159,
        158,
        49188,
        49187,
        49192,
        49191,
        49162,
        49161,
        49172,
        49171,
        57,
        51,
        157,
        156,
        61,
        60,
        53,
        47,
        10,
        106,
        64,
        56,
        50,
        19]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02\x06\x01\x06\x03'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0c\x02h2\x08http/1.1'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[21760] = TLSExtension(extType=21760).create(bytearray(b'\x00\x01\x00\x02\x00\x02'))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["131: IE 11 on Win 10"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49200,
        49199,
        49192,
        49191,
        49172,
        49171,
        159,
        158,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x0e\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x0f\x05h2-14\x08http/1.1'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["81: IE 11 on Win 10 Preview"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [60,
        47,
        61,
        53,
        5,
        10,
        49191,
        49171,
        49172,
        49195,
        49187,
        49196,
        49188,
        49161,
        49162,
        64,
        50,
        106,
        56,
        19,
        4]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x0e\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["36: IE 11 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49192,
        49191,
        49172,
        49171,
        159,
        158,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19,
        5,
        4]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["95: IE 11 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49192,
        49191,
        49172,
        49171,
        159,
        158,
        157,
        156,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        61,
        60,
        53,
        47,
        106,
        64,
        56,
        50,
        10,
        19,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x06\x01\x06\x03\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02'))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["102: IE 11 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49192,
        49191,
        49172,
        49171,
        159,
        158,
        57,
        51,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x06\x01\x06\x03\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["133: IE 11 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49192,
        49191,
        49172,
        49171,
        159,
        158,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x06\x01\x06\x03\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["143: IE 11 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [60,
        47,
        61,
        53,
        10,
        49191,
        49171,
        49172,
        49195,
        49187,
        49196,
        49188,
        49161,
        49162,
        64,
        50,
        106,
        56,
        19]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x0e\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x10\x06spdy/3\x08http/1.1'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["24: IE 11 on Win 8.1"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49192,
        159,
        158,
        157,
        156,
        49195,
        49187,
        49191,
        49172,
        49171,
        61,
        60,
        53,
        47,
        49196,
        49188,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x0e\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x10\x06spdy/3\x08http/1.1'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["71: IE 11 on Win 8.1"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49192,
        49191,
        49172,
        49171,
        159,
        158,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x02\x02'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x10\x06spdy/3\x08http/1.1'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["96: IE 11 on Win 8.1"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49192,
        49191,
        49172,
        49171,
        159,
        158,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x02\x02'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x10\x06spdy/3\x08http/1.1'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["104: IE 11 on Win 8.1"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49192,
        49191,
        49172,
        49171,
        159,
        158,
        57,
        51,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x12\x04\x01\x05\x01\x06\x01\x02\x01\x04\x03\x05\x03\x06\x03\x02\x03\x02\x02'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x10\x06spdy/3\x08http/1.1'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["134: IE 11 on Win 8.1"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [60,
        47,
        61,
        53,
        10,
        49191,
        49171,
        49172,
        49195,
        49187,
        49196,
        49188,
        49161,
        49162,
        64,
        50,
        106,
        56,
        19]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x0e\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x10\x06spdy/3\x08http/1.1'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["65: IE 11 on Win Phone 8.1"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49192,
        49191,
        49172,
        49171,
        159,
        158,
        157,
        156,
        61,
        60,
        53,
        47,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        106,
        64,
        56,
        50,
        10,
        19]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x0e\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x02\x02'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00\x10\x06spdy/3\x08http/1.1'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["106: IE 11 on Win Phone 8.1 Update"] = conversation

    conversation = Connect(host, port, version=(0, 2))
    node = conversation
    ciphers = [4,
        5,
        10,
        65664,
        458944,
        196736,
        9,
        393280,
        100,
        98,
        3,
        6,
        131200,
        262272,
        19,
        18,
        99]
    node = node.add_child(ClientHelloGenerator(ssl2=True, ciphers=ciphers, version=(3, 0), compression=[0]))
    node = node.add_child(ExpectServerHello())
    conversations["18: IE 6 on XP"] = conversation

    conversation = Connect(host, port, version=(0, 2))
    node = conversation
    ciphers = [4,
        5,
        10,
        65664,
        458944,
        196736,
        9,
        393280,
        100,
        98,
        3,
        6,
        131200,
        262272,
        19,
        18,
        99,
        255]
    node = node.add_child(ClientHelloGenerator(ssl2=True, ciphers=ciphers, version=(3, 0), compression=[0]))
    node = node.add_child(ExpectServerHello())
    conversations["100: IE 6 on XP"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [47,
        53,
        5,
        10,
        49161,
        49162,
        49171,
        49172,
        50,
        56,
        19,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["19: IE 7 on Vista"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [47,
        53,
        5,
        10,
        49171,
        49172,
        49161,
        49162,
        50,
        56,
        19,
        4]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["21: IE 8 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [4,
        5,
        10,
        9,
        100,
        98,
        3,
        6,
        19,
        18,
        99]
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0]))
    node = node.add_child(ExpectServerHello())
    conversations["20: IE 8 on XP"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [4,
        5,
        10,
        9,
        100,
        98,
        3,
        6,
        19,
        18,
        99]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["101: IE 8 on XP"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [47,
        53,
        5,
        10,
        49171,
        49172,
        49161,
        49162,
        50,
        56,
        19,
        4]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["23: IE 8-10 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49172,
        49171,
        53,
        47,
        49162,
        49161,
        56,
        50,
        10,
        19,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["113: IE 8-10 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [47,
        53,
        5,
        10,
        49171,
        49172,
        49161,
        49162,
        50,
        56,
        19,
        4]
    ext = OrderedDict()
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x17\x00\x18'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["22: IE 9 on Win 7"] = conversation

    conversation = Connect(host, port, version=(0, 2))
    node = conversation
    ciphers = [4,
        65664,
        5,
        47,
        51,
        50,
        10,
        458944,
        22,
        19,
        9,
        393280,
        21,
        18,
        3,
        131200,
        8,
        20,
        17,
        255]
    node = node.add_child(ClientHelloGenerator(ssl2=True, ciphers=ciphers, version=(3, 1), compression=[0]))
    node = node.add_child(ExpectServerHello())
    conversations["25: Java 6u45 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49161,
        49171,
        47,
        49156,
        49166,
        51,
        50,
        49159,
        49169,
        5,
        49154,
        49164,
        49160,
        49170,
        10,
        49155,
        49165,
        22,
        19,
        4,
        255]
    ext = OrderedDict()
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x17\x00\x01\x00\x03\x00\x13\x00\x15\x00\x06\x00\x07\x00\t\x00\n\x00\x18\x00\x0b\x00\x0c\x00\x19\x00\r\x00\x0e\x00\x0f\x00\x10\x00\x11\x00\x02\x00\x12\x00\x04\x00\x05\x00\x14\x00\x08\x00\x16'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["26: Java 7u25 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49187,
        49191,
        60,
        49189,
        49193,
        103,
        64,
        49161,
        49171,
        47,
        49156,
        49166,
        51,
        50,
        49159,
        49169,
        5,
        49154,
        49164,
        49195,
        49199,
        156,
        49197,
        49201,
        158,
        162,
        49160,
        49170,
        10,
        49155,
        49165,
        22,
        19,
        4,
        255]
    ext = OrderedDict()
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x17\x00\x01\x00\x03\x00\x13\x00\x15\x00\x06\x00\x07\x00\t\x00\n\x00\x18\x00\x0b\x00\x0c\x00\x19\x00\r\x00\x0e\x00\x0f\x00\x10\x00\x11\x00\x02\x00\x12\x00\x04\x00\x05\x00\x14\x00\x08\x00\x16'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x18\x06\x03\x06\x01\x05\x03\x05\x01\x04\x03\x04\x01\x03\x03\x03\x01\x02\x03\x02\x01\x02\x02\x01\x01'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["53: Java 8b132 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49187,
        49191,
        60,
        49189,
        49193,
        103,
        64,
        49161,
        49171,
        47,
        49156,
        49166,
        51,
        50,
        49195,
        49199,
        156,
        49197,
        49201,
        158,
        162,
        49160,
        49170,
        10,
        49155,
        49165,
        22,
        19,
        255]
    ext = OrderedDict()
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x17\x00\x01\x00\x03\x00\x13\x00\x15\x00\x06\x00\x07\x00\t\x00\n\x00\x18\x00\x0b\x00\x0c\x00\x19\x00\r\x00\x0e\x00\x0f\x00\x10\x00\x11\x00\x02\x00\x12\x00\x04\x00\x05\x00\x14\x00\x08\x00\x16'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x03\x06\x01\x05\x03\x05\x01\x04\x03\x04\x01\x04\x02\x02\x03\x02\x01\x02\x02'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["146: Java 8u111 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49188,
        49192,
        61,
        49190,
        49194,
        107,
        106,
        49162,
        49172,
        53,
        49157,
        49167,
        57,
        56,
        49187,
        49191,
        60,
        49189,
        49193,
        103,
        64,
        49161,
        49171,
        47,
        49156,
        49166,
        51,
        50,
        49196,
        49195,
        49200,
        157,
        49198,
        49202,
        159,
        163,
        49199,
        156,
        49197,
        49201,
        158,
        162,
        49160,
        49170,
        10,
        49155,
        49165,
        22,
        19,
        255]
    ext = OrderedDict()
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x14\x00\x17\x00\x18\x00\x19\x00\t\x00\n\x00\x0b\x00\x0c\x00\r\x00\x0e\x00\x16'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x03\x06\x01\x05\x03\x05\x01\x04\x03\x04\x01\x04\x02\x02\x03\x02\x01\x02\x02'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["147: Java 8u161 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49187,
        49191,
        60,
        49189,
        49193,
        103,
        64,
        49161,
        49171,
        47,
        49156,
        49166,
        51,
        50,
        49195,
        49199,
        156,
        49197,
        49201,
        158,
        162,
        49160,
        49170,
        10,
        49155,
        49165,
        22,
        19,
        49159,
        49169,
        5,
        49154,
        49164,
        4,
        255]
    ext = OrderedDict()
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x17\x00\x01\x00\x03\x00\x13\x00\x15\x00\x06\x00\x07\x00\t\x00\n\x00\x18\x00\x0b\x00\x0c\x00\x19\x00\r\x00\x0e\x00\x0f\x00\x10\x00\x11\x00\x02\x00\x12\x00\x04\x00\x05\x00\x14\x00\x08\x00\x16'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x18\x06\x03\x06\x01\x05\x03\x05\x01\x04\x03\x04\x01\x03\x03\x03\x01\x02\x03\x02\x01\x02\x02\x01\x01'))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["86: Java 8u31 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [49196,
        49195,
        49200,
        157,
        49198,
        49202,
        159,
        163,
        49199,
        156,
        49197,
        49201,
        158,
        162,
        49188,
        49192,
        61,
        49190,
        49194,
        107,
        106,
        49162,
        49172,
        53,
        49157,
        49167,
        57,
        56,
        49187,
        49191,
        60,
        49189,
        49193,
        103,
        64,
        49161,
        49171,
        47,
        49156,
        49166,
        51,
        50,
        49160,
        49170,
        10,
        49155,
        49165,
        22,
        19,
        255]
    ext = OrderedDict()
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x1e\x00\x17\x00\x18\x00\x19\x00\t\x00\n\x00\x0b\x00\x0c\x00\r\x00\x0e\x00\x16\x01\x00\x01\x01\x01\x02\x01\x03\x01\x04'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x14\x06\x03\x06\x01\x05\x03\x05\x01\x04\x03\x04\x01\x04\x02\x02\x03\x02\x01\x02\x02'))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[17] = TLSExtension(extType=17).create(bytearray(b'\x00\x0e\x02\x00\x04\x00\x00\x00\x00\x01\x00\x04\x00\x00\x00\x00'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["148: Java 9.0.4 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [57,
        56,
        53,
        22,
        19,
        10,
        51,
        50,
        47,
        7,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["27: OpenSSL 0.9.8y on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49200,
        49196,
        49192,
        49188,
        49172,
        49162,
        49186,
        49185,
        163,
        159,
        107,
        106,
        57,
        56,
        136,
        135,
        49202,
        49198,
        49194,
        49190,
        49167,
        49157,
        157,
        61,
        53,
        132,
        49170,
        49160,
        49180,
        49179,
        22,
        19,
        49165,
        49155,
        10,
        49199,
        49195,
        49191,
        49187,
        49171,
        49161,
        49183,
        49182,
        162,
        158,
        103,
        64,
        51,
        50,
        154,
        153,
        69,
        68,
        49201,
        49197,
        49193,
        49189,
        49166,
        49156,
        156,
        60,
        47,
        150,
        65,
        7,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00 \x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x01\x01'))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["28: OpenSSL 1.0.1h on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49200,
        49196,
        49192,
        49188,
        49172,
        49162,
        163,
        159,
        107,
        106,
        57,
        56,
        136,
        135,
        49202,
        49198,
        49194,
        49190,
        49167,
        49157,
        157,
        61,
        53,
        132,
        49199,
        49195,
        49191,
        49187,
        49171,
        49161,
        162,
        158,
        103,
        64,
        51,
        50,
        154,
        153,
        69,
        68,
        49201,
        49197,
        49193,
        49189,
        49166,
        49156,
        156,
        60,
        47,
        150,
        65,
        7,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        49170,
        49160,
        22,
        19,
        49165,
        49155,
        10,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["99: OpenSSL 1.0.1l on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49200,
        49196,
        49192,
        49188,
        49172,
        49162,
        165,
        163,
        161,
        159,
        107,
        106,
        105,
        104,
        57,
        56,
        55,
        54,
        136,
        135,
        134,
        133,
        49202,
        49198,
        49194,
        49190,
        49167,
        49157,
        157,
        61,
        53,
        132,
        49199,
        49195,
        49191,
        49187,
        49171,
        49161,
        164,
        162,
        160,
        158,
        103,
        64,
        63,
        62,
        51,
        50,
        49,
        48,
        154,
        153,
        152,
        151,
        69,
        68,
        67,
        66,
        49201,
        49197,
        49193,
        49189,
        49166,
        49156,
        156,
        60,
        47,
        150,
        65,
        7,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        49170,
        49160,
        22,
        19,
        16,
        13,
        49165,
        49155,
        10,
        21,
        18,
        15,
        12,
        9,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x1a\x00\x17\x00\x19\x00\x1c\x00\x1b\x00\x18\x00\x1a\x00\x16\x00\x0e\x00\r\x00\x0b\x00\x0c\x00\t\x00\n'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["121: OpenSSL 1.0.2e on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [107,
        106,
        105,
        104,
        61,
        57,
        56,
        55,
        54,
        53,
        103,
        64,
        63,
        62,
        60,
        51,
        50,
        49,
        48,
        47,
        5,
        4,
        19,
        13,
        22,
        16,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["29: Opera 12.15 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        102,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        5,
        4,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[30031] = TLSExtension(extType=30031).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 2), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["30: Opera 15 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49162,
        49172,
        57,
        107,
        53,
        61,
        49159,
        49161,
        49187,
        49169,
        49171,
        49191,
        51,
        103,
        50,
        5,
        4,
        47,
        60,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[30031] = TLSExtension(extType=30031).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 2), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["39: Opera 16 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49162,
        49172,
        57,
        107,
        53,
        61,
        49159,
        49161,
        49187,
        49169,
        49171,
        49191,
        51,
        103,
        50,
        5,
        4,
        47,
        60,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[65281] = TLSExtension(extType=65281).create(bytearray(b'\x00'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00 \x06spdy/2\x06spdy/3\x08spdy/3.1\x08http/1.1'))
    ext[30031] = TLSExtension(extType=30031).create(bytearray(b''))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x05\x01\x02\x01\x04\x03\x05\x03\x02\x03\x04\x02\x02\x02'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["43: Opera 17 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        49160,
        49200,
        49199,
        49192,
        49191,
        49172,
        49171,
        49170,
        157,
        156,
        61,
        60,
        53,
        47,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x02\x01\x05\x01\x06\x01\x04\x03\x02\x03\x05\x03\x06\x03'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00.\x02h2\x05h2-16\x05h2-15\x05h2-14\x08spdy/3.1\x06spdy/3\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["138: Safari 10 on OS X 10.12"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        49160,
        49200,
        49199,
        49192,
        49191,
        49172,
        49171,
        49170,
        157,
        156,
        61,
        60,
        53,
        47,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x10\x04\x01\x02\x01\x05\x01\x06\x01\x04\x03\x02\x03\x05\x03\x06\x03'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00.\x02h2\x05h2-16\x05h2-15\x05h2-14\x08spdy/3.1\x06spdy/3\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    ext[23] = TLSExtension(extType=23).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["140: Safari 10 on iOS 10"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [255,
        49188,
        49187,
        49162,
        49161,
        49159,
        49160,
        49192,
        49191,
        49172,
        49171,
        49169,
        49170,
        49190,
        49189,
        49194,
        49193,
        49156,
        49157,
        49154,
        49155,
        49166,
        49167,
        49164,
        49165,
        61,
        60,
        47,
        5,
        4,
        53,
        10,
        103,
        107,
        51,
        57,
        22]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\n\x05\x01\x04\x01\x02\x01\x04\x03\x02\x03'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["31: Safari 5 on iOS 5.1.1"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49162,
        49161,
        49159,
        49160,
        49171,
        49172,
        49169,
        49170,
        49156,
        49157,
        49154,
        49155,
        49166,
        49167,
        49164,
        49165,
        47,
        5,
        4,
        53,
        10,
        9,
        3,
        8,
        6,
        50,
        51,
        56,
        57,
        22,
        21,
        20,
        19,
        18,
        17]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["32: Safari 5.1.9 on OS X 10.6.8"] = conversation

    conversation = Connect(host, port, version=(3, 3))
    node = conversation
    ciphers = [255,
        49188,
        49187,
        49162,
        49161,
        49159,
        49160,
        49192,
        49191,
        49172,
        49171,
        49169,
        49170,
        49190,
        49189,
        49194,
        49193,
        49156,
        49157,
        49154,
        49155,
        49166,
        49167,
        49164,
        49165,
        61,
        60,
        47,
        5,
        4,
        53,
        10,
        103,
        107,
        51,
        57,
        22,
        49158,
        49168,
        49153,
        49163,
        59,
        2,
        1]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\n\x05\x01\x04\x01\x02\x01\x04\x03\x02\x03'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["33: Safari 6 on iOS 6.0.1"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49161,
        49159,
        49160,
        49172,
        49171,
        49169,
        49170,
        49156,
        49157,
        49154,
        49155,
        49166,
        49167,
        49164,
        49165,
        47,
        5,
        4,
        53,
        10,
        51,
        57,
        22]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["34: Safari 6.0.4 on OS X 10.8.4"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49188,
        49187,
        49162,
        49161,
        49159,
        49160,
        49192,
        49191,
        49172,
        49171,
        49169,
        49170,
        49190,
        49189,
        49194,
        49193,
        49157,
        49156,
        49154,
        49155,
        49167,
        49166,
        49164,
        49165,
        61,
        60,
        47,
        5,
        4,
        53,
        10,
        103,
        107,
        51,
        57,
        22]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\n\x05\x01\x04\x01\x02\x01\x04\x03\x02\x03'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["35: Safari 7 on OS X 10.9"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49188,
        49187,
        49162,
        49161,
        49159,
        49160,
        49192,
        49191,
        49172,
        49171,
        49169,
        49170,
        49190,
        49189,
        49194,
        49193,
        49157,
        49156,
        49154,
        49155,
        49167,
        49166,
        49164,
        49165,
        61,
        60,
        47,
        5,
        4,
        53,
        10,
        103,
        107,
        51,
        57,
        22]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\n\x05\x01\x04\x01\x02\x01\x04\x03\x02\x03'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["63: Safari 7 on iOS 7.1"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49188,
        49187,
        49162,
        49161,
        49160,
        49192,
        49191,
        49172,
        49171,
        49170,
        49190,
        49189,
        49157,
        49156,
        49155,
        49194,
        49193,
        49167,
        49166,
        49165,
        107,
        103,
        57,
        51,
        22,
        61,
        60,
        53,
        47,
        10,
        49159,
        49169,
        49154,
        49164,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\n\x05\x01\x04\x01\x02\x01\x04\x03\x02\x03'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["87: Safari 8 on OS X 10.10"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49188,
        49187,
        49162,
        49161,
        49160,
        49192,
        49191,
        49172,
        49171,
        49170,
        49190,
        49189,
        49157,
        49156,
        49155,
        49194,
        49193,
        49167,
        49166,
        49165,
        107,
        103,
        57,
        51,
        22,
        61,
        60,
        53,
        47,
        10,
        49159,
        49169,
        49154,
        49164,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\n\x05\x01\x04\x01\x02\x01\x04\x03\x02\x03'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["75: Safari 8 on iOS 8.0 Beta"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49188,
        49187,
        49162,
        49161,
        49160,
        49192,
        49191,
        49172,
        49171,
        49170,
        49190,
        49189,
        49157,
        49156,
        49155,
        49194,
        49193,
        49167,
        49166,
        49165,
        107,
        103,
        57,
        51,
        22,
        61,
        60,
        53,
        47,
        10,
        49159,
        49169,
        49154,
        49164,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\n\x05\x01\x04\x01\x02\x01\x04\x03\x02\x03'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["85: Safari 8 on iOS 8.4"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        49160,
        49200,
        49199,
        49192,
        49191,
        49172,
        49171,
        49170,
        157,
        156,
        61,
        60,
        53,
        47,
        10,
        49159,
        49169,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x0c\x05\x01\x04\x01\x02\x01\x05\x03\x04\x03\x02\x03'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00.\x02h2\x05h2-16\x05h2-15\x05h2-14\x08spdy/3.1\x06spdy/3\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["111: Safari 9 on OS X 10.11"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49196,
        49195,
        49188,
        49187,
        49162,
        49161,
        49160,
        49200,
        49199,
        49192,
        49191,
        49172,
        49171,
        49170,
        157,
        156,
        61,
        60,
        53,
        47,
        10,
        49159,
        49169,
        5,
        4]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x0c\x05\x01\x04\x01\x02\x01\x05\x03\x04\x03\x02\x03'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    ext[16] = TLSExtension(extType=16).create(bytearray(b'\x00.\x02h2\x05h2-16\x05h2-15\x05h2-14\x08spdy/3.1\x06spdy/3\x08http/1.1'))
    ext[5] = TLSExtension(extType=5).create(bytearray(b'\x01\x00\x00\x00\x00'))
    ext[18] = TLSExtension(extType=18).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["114: Safari 9 on iOS 9"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        5,
        4,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[13172] = TLSExtension(extType=13172).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["44: Tor 17.0.9 on Win 7"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49200,
        49196,
        49192,
        49188,
        49172,
        49162,
        163,
        159,
        107,
        106,
        57,
        56,
        136,
        135,
        49202,
        49198,
        49194,
        49190,
        49167,
        49157,
        157,
        61,
        53,
        132,
        49170,
        49160,
        22,
        19,
        49165,
        49155,
        10,
        49199,
        49195,
        49191,
        49187,
        49171,
        49161,
        162,
        158,
        103,
        64,
        51,
        50,
        154,
        153,
        69,
        68,
        49201,
        49197,
        49193,
        49189,
        49166,
        49156,
        156,
        60,
        47,
        150,
        65,
        7,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x18\x00\x17'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00 \x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x01\x01'))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["92: Yahoo Slurp Jan 2015 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49200,
        49196,
        49192,
        49188,
        49172,
        49162,
        163,
        159,
        107,
        106,
        57,
        56,
        136,
        135,
        49202,
        49198,
        49194,
        49190,
        49167,
        49157,
        157,
        61,
        53,
        132,
        49170,
        49160,
        22,
        19,
        49165,
        49155,
        10,
        49199,
        49195,
        49191,
        49187,
        49171,
        49161,
        162,
        158,
        103,
        64,
        51,
        50,
        154,
        153,
        69,
        68,
        49201,
        49197,
        49193,
        49189,
        49166,
        49156,
        156,
        60,
        47,
        150,
        65,
        7,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x04\x00\x18\x00\x17'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00 \x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03\x01\x01'))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["73: Yahoo Slurp Jun 2014 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [255,
        49162,
        49172,
        136,
        135,
        57,
        56,
        49167,
        49157,
        132,
        53,
        49159,
        49161,
        49169,
        49171,
        69,
        68,
        51,
        50,
        49164,
        49166,
        49154,
        49156,
        150,
        65,
        4,
        5,
        47,
        49160,
        49170,
        22,
        19,
        49165,
        49155,
        65279,
        10]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x00\x06\x00\x17\x00\x18\x00\x19'))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x01\x00'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["42: Yahoo Slurp Oct 2013 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 0))
    node = conversation
    ciphers = [10,
        5,
        4]
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 0), compression=[0]))
    node = node.add_child(ExpectServerHello())
    conversations["52: YandexBot 3.0 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49200,
        49196,
        49192,
        49188,
        49172,
        49162,
        49186,
        49185,
        163,
        159,
        107,
        106,
        57,
        56,
        49202,
        49198,
        49194,
        49190,
        49167,
        49157,
        157,
        61,
        53,
        49170,
        49160,
        49180,
        49179,
        22,
        19,
        49165,
        49155,
        10,
        49199,
        49195,
        49191,
        49187,
        49171,
        49161,
        49183,
        49182,
        162,
        158,
        103,
        64,
        51,
        50,
        49201,
        49197,
        49193,
        49189,
        49166,
        49156,
        156,
        60,
        47,
        7,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03'))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["93: YandexBot Jan 2015 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [57,
        56,
        53,
        22,
        19,
        10,
        51,
        50,
        47,
        7,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 1), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["68: YandexBot May 2014 on unknown"] = conversation

    conversation = Connect(host, port, version=(3, 1))
    node = conversation
    ciphers = [49200,
        49196,
        49192,
        49188,
        49172,
        49162,
        49186,
        49185,
        163,
        159,
        107,
        106,
        57,
        56,
        49202,
        49198,
        49194,
        49190,
        49167,
        49157,
        157,
        61,
        53,
        49170,
        49160,
        49180,
        49179,
        22,
        19,
        49165,
        49155,
        10,
        49199,
        49195,
        49191,
        49187,
        49171,
        49161,
        49183,
        49182,
        162,
        158,
        103,
        64,
        51,
        50,
        49201,
        49197,
        49193,
        49189,
        49166,
        49156,
        156,
        60,
        47,
        7,
        49169,
        49159,
        49164,
        49154,
        5,
        4,
        21,
        18,
        9,
        20,
        17,
        8,
        6,
        3,
        255]
    ext = OrderedDict()
    ext[0] = SNIExtension().create(bytearray(host, "ascii"))
    ext[11] = TLSExtension(extType=11).create(bytearray(b'\x03\x00\x01\x02'))
    ext[10] = TLSExtension(extType=10).create(bytearray(b'\x002\x00\x0e\x00\r\x00\x19\x00\x0b\x00\x0c\x00\x18\x00\t\x00\n\x00\x16\x00\x17\x00\x08\x00\x06\x00\x07\x00\x14\x00\x15\x00\x04\x00\x05\x00\x12\x00\x13\x00\x01\x00\x02\x00\x03\x00\x0f\x00\x10\x00\x11'))
    ext[35] = TLSExtension(extType=35).create(bytearray(b''))
    ext[13] = TLSExtension(extType=13).create(bytearray(b'\x00\x1e\x06\x01\x06\x02\x06\x03\x05\x01\x05\x02\x05\x03\x04\x01\x04\x02\x04\x03\x03\x01\x03\x02\x03\x03\x02\x01\x02\x02\x02\x03'))
    ext[15] = TLSExtension(extType=15).create(bytearray(b'\x01'))
    node = node.add_child(ClientHelloGenerator(ciphers=ciphers, version=(3, 3), compression=[0], extensions=ext))
    node = node.add_child(ExpectServerHello())
    conversations["78: YandexBot Sep 2014 on unknown"] = conversation


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
