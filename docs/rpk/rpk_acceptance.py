#!/usr/bin/env python3
"""Acceptance for the RFC 7250 certificate-type generators asked for in
README.md.

Run it before the fork change and it fails, naming what is missing. Run it
after and every check passes. Nothing here needs a peer unless --peer is
given.

    venv/bin/python3 docs/rpk/rpk_acceptance.py
    venv/bin/python3 docs/rpk/rpk_acceptance.py --peer 127.0.0.1:44330
"""

import argparse
import os
import socket
import sys

# Python puts this script's own directory on sys.path, not the caller's cwd, so
# the repository root has to be added explicitly or `import tlsfuzzer` fails
# even when run from the root.
sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

FAILURES = []


def check(label, condition, detail=""):
    if condition:
        print("  ok    %s" % label)
    else:
        print("  FAIL  %s %s" % (label, detail))
        FAILURES.append(label)


def load_helpers():
    """Import the fork, telling the two failure modes apart.

    A missing generator is this ask, not yet done. Anything that stops the
    import outright is an environment problem instead, and would otherwise read
    as the same one.
    """
    try:
        import tlsfuzzer.helpers as helpers
    except ImportError as exc:
        print("tlsfuzzer does not import: %s" % exc)
        print()
        print("This is not the RPK ask. Install the dependencies into the venv:")
        print("  venv/bin/python3 -m pip install -r requirements.txt")
        sys.exit(2)
    except AttributeError as exc:
        print("tlsfuzzer does not import: %s" % exc)
        print()
        print("This is not the RPK ask. tlsfuzzer and the installed tlslite-ng")
        print("are out of step with each other. Reinstall to the pinned version:")
        print("  venv/bin/python3 -m pip install -r requirements.txt")
        sys.exit(2)
    return helpers


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--peer", help="host:port of an RPK-capable TLS 1.3 server")
    args = parser.parse_args()

    helpers = load_helpers()

    print("1. the generators exist")
    missing = [
        name
        for name in ("server_cert_type_ext_gen", "client_cert_type_ext_gen")
        if not hasattr(helpers, name)
    ]
    if missing:
        print("  FAIL  tlsfuzzer.helpers is missing: %s" % ", ".join(missing))
        print()
        print("This is the ask. See README.md section 5.")
        sys.exit(1)
    print("  ok    server_cert_type_ext_gen, client_cert_type_ext_gen")

    print("2. the extension numbers (RFC 7250 s:3)")
    server_ext = helpers.server_cert_type_ext_gen()
    client_ext = helpers.client_cert_type_ext_gen()
    check("server_certificate_type is 20", server_ext.extType == 20, server_ext.extType)
    check("client_certificate_type is 19", client_ext.extType == 19, client_ext.extType)

    print("3. the client body is a counted list, most preferred first")
    rpk = helpers.CERTIFICATE_TYPE_RAW_PUBLIC_KEY
    x509 = helpers.CERTIFICATE_TYPE_X509
    check("RawPublicKey is 2", rpk == 2, rpk)
    check("X509 is 0", x509 == 0, x509)

    only_rpk = bytes(helpers.server_cert_type_ext_gen([rpk]).extData)
    check("[RawPublicKey] encodes as 0102", only_rpk == b"\x01\x02", only_rpk.hex())

    both = bytes(helpers.server_cert_type_ext_gen([rpk, x509]).extData)
    check("[RawPublicKey, X509] encodes as 020200", both == b"\x02\x02\x00", both.hex())

    default = bytes(helpers.server_cert_type_ext_gen().extData)
    check("the default solicits raw public keys", default == b"\x01\x02", default.hex())

    print("4. the list length is guarded")
    for bad, label in (([], "empty list"), ([rpk] * 256, "256 types")):
        try:
            helpers.server_cert_type_ext_gen(bad)
            check("%s is refused" % label, False, "it was accepted")
        except ValueError:
            check("%s is refused" % label, True)

    print("5. it survives being written into a ClientHello")
    import tlslite.constants
    import tlslite.messages

    hello = tlslite.messages.ClientHello()
    hello.create(
        (3, 3),
        bytearray(32),
        bytearray(0),
        [tlslite.constants.CipherSuite.TLS_AES_128_GCM_SHA256],
        extensions=[helpers.server_cert_type_ext_gen([rpk])],
    )
    raw = bytes(hello.write())
    # extension header on the wire: type 0x0014, length 0x0002, body 0102
    check("extension 20 is on the wire", b"\x00\x14\x00\x02\x01\x02" in raw)

    if args.peer:
        print("6. a live RPK-capable peer accepts the solicitation")
        host, _, port = args.peer.partition(":")
        try:
            with socket.create_connection((host, int(port)), timeout=5):
                check("peer is reachable", True)
        except OSError as exc:
            check("peer is reachable", False, str(exc))
        print("     (a full handshake check belongs in the conversation script")
        print("      that calls these generators - see README.md section 7)")

    print()
    if FAILURES:
        print("FAILED: %d check(s) - %s" % (len(FAILURES), "; ".join(FAILURES)))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
