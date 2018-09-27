from __future__ import print_function
from cscan.messages import ClientHello
from tlslite.utils.codec import Parser
from tlslite.constants import ExtensionType, GroupName
from tlslite.extensions import ClientKeyShareExtension
from tlslite.keyexchange import X25519_ORDER_SIZE, X448_ORDER_SIZE
import json
import sys

"""
Parser of the ssllabs v3 API getClient call and converts it to tlsfuzzer.

Download the clients from https://api.ssllabs.com/api/v3/getClients
"""

def fake_priv_for_group(group):
    if group == GroupName.x25519:
        return bytearray([5] * X25519_ORDER_SIZE)
    elif group == GroupName.x448:
        return bytearray([5] * X448_ORDER_SIZE)
    elif group in GroupName.allEC:
        return 5
    elif group in GroupName.allFF:
        return bytearray([5])
    return None


def client_key_share_gen(extension):
    parsedExt = ClientKeyShareExtension().parse(
        Parser(ch_ext.extData))
    return "ClientKeyShareExtension().create([{0}])".format(
        ", ".join("KeyShareEntry().create({0!r}, {1!r}, {2!r})".format(
                  i.group, i.key_exchange, fake_priv_for_group(i.group)) for
                  i in parsedExt.client_shares))


with open(sys.argv[1]) as json_file:
    try:
        clients = json.load(json_file)
    except ValueError:
        print("Can't load JSON file")
        raise

for client in sorted(clients, key=lambda i: "{0[name]} {0[version]} {1}"
                     .format(i, i["platform"] if "platform" in i else "None")):
    #print("{0} {1} on {2}".format(client["name"],
    #                              client["version"],
    #                              client["platform"] if "platform" in client
    #                              else "unknown"))
    space = "    "
    ch_bytes = bytearray.fromhex(client["hexHandshakeBytes"])
    opt = []
    if client["handshakeFormat"] == "v3":
        ch = ClientHello(ssl2=False).parse(Parser(ch_bytes[6:]))
    #    print("Record layer protocol version: {0}, {1}".format(ch_bytes[1],
    #                                                           ch_bytes[2]))
    #    print("Hello: {0:}".format(ch))
    #    print("min version: ({0[0]}, {0[1]})".format(
    #          divmod(client["lowestProtocol"], 256)))
    #    print("max version: ({0[0]}, {0[1]})".format(
    #          divmod(client["highestProtocol"], 256)))
        print("{space}conversation = Connect(host, port, version=({0}, {1}))"
              .format(ch_bytes[1], ch_bytes[2], space=space))
    elif client["handshakeFormat"] == "v2":
        ch = ClientHello(ssl2=True).parse(Parser(ch_bytes[3:]))
        print("{s}conversation = Connect(host, port, version=(0, 2))".format(
              s=space))
        opt.append("ssl2=True")
    else:
        raise ValueError("Unknown handshakeFormat")
    print("{space}node = conversation".format(space=space))
    print("{s}ciphers = [{0}]".format(",\n{space}{space}".format(
                                          space=space).join(str(i) for i
                                          in ch.cipher_suites),
                                          s=space))
    opt.append("ciphers=ciphers")
    opt.append("version={0!r}".format(ch.client_version))
    opt.append("compression={0!r}".format(ch.compression_methods))
    if ch.extensions is not None:
        print("{s}ext = OrderedDict()".format(s=space))
        for ch_ext in ch.extensions:
            if ch_ext.extType == ExtensionType.server_name:
                extCreate = "SNIExtension().create(bytearray(host, \"ascii\"))"
            elif ch_ext.extType == ExtensionType.key_share:
                extCreate = client_key_share_gen(ch_ext)
            else:
                extCreate = "TLSExtension(extType={0}).create({1!r})"\
                        .format(ch_ext.extType, ch_ext.extData)
            print("{s}ext[{0}] = {1}".format(ch_ext.extType, extCreate,
                                             s=space))
        opt.append("extensions=ext")
    print("{s}node = node.add_child(ClientHelloGenerator({0}))"\
          .format(", ".join(opt), s=space))
    print("{s}node = node.add_child(ExpectServerHello())".format(s=space))
    print("{s}conversations[\"{0[id]}: {0[name]} {0[version]} on {1}\"] = "
          "conversation".format(client, client["platform"] if "platform"
                                in client else "unknown", s=space))
    print("")
