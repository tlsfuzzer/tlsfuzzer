# Author: Hubert Kario, (c) 2017
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Verify that different iOS clients can connect to the server under test."""

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
from tlslite.extensions import SNIExtension, ECPointFormatsExtension, \
        SupportedGroupsExtension, SignatureAlgorithmsExtension, NPNExtension, \
        TLSExtension
from tlsfuzzer.utils.ordered_dict import OrderedDict

from tlslite.constants import CipherSuite, AlertLevel, AlertDescription, \
        ExtensionType, GroupName, ECPointFormat, HashAlgorithm, \
        SignatureAlgorithm


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
    print(" --help         this message")


def main():
    host = "localhost"
    port = 4433
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

    conversation = Connect(host, port)
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

    print("Test end")
    print("successful: {0}".format(good))
    print("failed: {0}".format(bad))
    failed_sorted = sorted(failed, key=natural_sort_keys)
    print("  {0}".format('\n  '.join(repr(i) for i in failed_sorted)))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
