# RFC 7250 raw public keys, for the tlsfuzzer fork

A specification for `nrathaus/tlsfuzzer`: the measured gap, the hook to change,
the code, and an acceptance script that can be run before and after.

**The ask is small on purpose.** One constant block and two generator functions
in `tlsfuzzer/helpers.py`. It deliberately stops short of implementing RFC 7250,
and section 6 says why that half is not being asked for.

> **Status: landed 2026-08-27.** Section 5 is implemented in
> `tlsfuzzer/helpers.py` and `rpk_acceptance.py` passes all five offline checks.
> Sections 1 to 6 are kept as the rationale for the shape of the change; section
> 8 is what remains, and it is Penzzer-side.

## 1. What Penzzer needs it for

`src/tool/modules/ssl_tls/rpk_signature_algorithms_cert.py` builds a ClientHello
that solicits raw public keys and also sends `signature_algorithms_cert`. The
pairing is the point: a peer answering with a raw public key has no certificate
to choose a signature algorithm for, while `signature_algorithms_cert`
(RFC 8446 s:4.2.3) is precisely a constraint on certificates, so the peer has to
decide what a constraint on an absent thing means.

That shape is CVE-2026-14457 in OpenSSL, fixed in 3.6.4 / 3.5.8 / 3.4.7 / 4.0.2,
where a server with RPK enabled and only a private key configured dereferences
the certificate it does not have. The module is not written against OpenSSL - it
is written against the protocol, and any RPK-capable peer is a target.

## 2. Why the fork rather than Penzzer

Two measurements, both taken 2026-08-27 against the tree.

**Naming an extension is the convention in the 151 modules in
`src/tool/modules/ssl_tls/`.** alpn, server_name, early_data - all
`ExtensionType.*`. 5 of the 151 files do pass a bare number to
`TLSExtension(extType=...)`, so this is a convention rather than a rule, and it
is worth being exact about what those 5 are doing:

| file | why the number is bare |
| --- | --- |
| `extensions.py`, `large_hello.py` | deliberately unassigned numbers (80, 90, 65283) - the point is that they are *not* real extensions |
| `client_compatibility.py` | verbatim replay of captured ClientHellos, raw cipher lists and raw extension bodies alike |
| `lengths.py` | `extType=1` beside `ExtensionType.max_fragment_length` as the dict key on the same line |
| `record_size_limit.py` | bare `ext[1]`, for a constant tlslite does name |

Only the last is squarely a raw assigned number where a name existed, and it is
one line in one file. A Penzzer-side `SERVER_CERTIFICATE_TYPE = 20` would be a
real, assigned extension number that is named *nowhere* - not in tlslite, not in
tlsfuzzer - defined in the consumer rather than in the library that owns protocol
constants. `CLAUDE.md`'s related-repositories rule calls that a competing copy
and asks for a fork change instead.

The stronger half of the argument is the next paragraph, not this one.

**`helpers.py` already owns this exact class of thing:** `key_share_gen`,
`key_share_ext_gen`, `psk_ext_gen`, `session_ticket_ext_gen`. An extension
generator for a conversation script to call is what the file is for.

## 3. What is there today, and what is not

Measured against `tlsfuzzer/tlsfuzzer` master and `tlsfuzzer/tlslite-ng` master,
2026-08-27.

**tlslite-ng master has no RFC 7250 support at all.** No
`client_certificate_type` / `server_certificate_type` in `ExtensionType`, no
extension class. Every `RawPublicKey` hit in that tree is RSA raw-public-key
arithmetic (`_rawPublicKeyOp`), which is unrelated.

**tlsfuzzer master has four lines, and both pairs are bookkeeping:**

| `expect.py` | what it does |
| --- | --- |
| 1411, 1412 | 19 and 20 listed in `TLS_1_3_CR_FORBIDDEN` - rejected in a CertificateRequest |
| 1834, 1836 | 19 and 20 listed in `ee_supported` - tolerated in EncryptedExtensions |

The second list carries the comment *"fix these constants, when the extensions
are implemented"*, which is upstream stating outright that they are not. None of
the 171 scripts in `scripts/` mentions `certificate_type`.

**One consequence worth knowing:** because 20 is already in `ee_supported`, a
server echoing `server_certificate_type` back does **not** trip
`ExpectEncryptedExtensions`. So a conversation can read past the ServerHello
today. What still cannot be read is the `Certificate` message itself - see
section 6.

## 4. The wire format

RFC 7250 s:3. The extension is asymmetric, and getting that backwards is the
easy mistake: a **client** sends a list, a **server** answers with a single byte.

```
struct {
    select(ClientOrServerExtension) {
        case client:
          CertificateType server_certificate_types<1..2^8-1>;
        case server:
          CertificateType server_certificate_type;
    }
} ServerCertTypeExtension;
```

So the client's extension body is a one-byte list length followed by that many
type values, most preferred first. `client_certificate_type` (19) has the same
shape.

| `CertificateType` | value |
| --- | --- |
| `X509` | 0 |
| `RawPublicKey` | 2 |

Body for "raw public keys only": `01 02`. For "raw public keys, then X.509":
`02 02 00`.

## 5. The change

In `tlsfuzzer/helpers.py`, beside `key_share_ext_gen`.

```python
# RFC 7250 s:3. tlslite has no ExtensionType member for either of these, so the
# numbers are named here rather than at every call site. Note that tlslite's
# ExtensionType.cert_type (9, RFC 6091) and this module's
# client_cert_types_to_ids() (RFC 5246 ClientCertificateType) are both different
# registries that happen to have confusable names.
CLIENT_CERTIFICATE_TYPE = 19
SERVER_CERTIFICATE_TYPE = 20

CERTIFICATE_TYPE_X509 = 0
CERTIFICATE_TYPE_RAW_PUBLIC_KEY = 2


def _cert_type_ext_gen(ext_type, types):
    """The client half of an RFC 7250 certificate-type extension.

    A client sends a preference list, a server answers with one value, so this
    builds the client form only: a one-byte count then the values.
    """
    types = list(types)
    if not 1 <= len(types) <= 255:
        raise ValueError("need between 1 and 255 certificate types")
    body = bytearray([len(types)]) + bytearray(types)
    return TLSExtension(extType=ext_type).create(body)


def server_cert_type_ext_gen(types=(CERTIFICATE_TYPE_RAW_PUBLIC_KEY,)):
    """Solicit these certificate types from the server, most preferred first."""
    return _cert_type_ext_gen(SERVER_CERTIFICATE_TYPE, types)


def client_cert_type_ext_gen(types=(CERTIFICATE_TYPE_RAW_PUBLIC_KEY,)):
    """Offer these certificate types for our own credential."""
    return _cert_type_ext_gen(CLIENT_CERTIFICATE_TYPE, types)
```

**Two edits beyond the block itself.** `TLSExtension` is *not* currently imported
in `helpers.py` - line 11 brings in `KeyShareEntry`, `PreSharedKeyExtension`,
`PskIdentity`, `ClientKeyShareExtension` and `SessionTicketExtension` only - so it
has to be added:

```python
from tlslite.extensions import KeyShareEntry, PreSharedKeyExtension, \
        PskIdentity, ClientKeyShareExtension, SessionTicketExtension, \
        TLSExtension
```

Without it the module still imports cleanly and the failure only appears when a
generator is *called*, as `NameError: name 'TLSExtension' is not defined`. The
two new public names and the four constants also belong in `__all__`
(`helpers.py` line 18), which lists every other public helper in the file.

**A naming hazard worth two sentences.** `helpers.py` line 221 already has
`client_cert_types_to_ids()`, and it is **not** related: it converts RFC 5246
`ClientCertificateType` names (`rsa_sign`, `dss_sign`) used in a TLS 1.2
CertificateRequest. tlslite adds a third confusable name, `ExtensionType.cert_type`,
which is 9 - RFC 6091's certificate type extension, also unrelated. RFC 7250's
`CertificateType` is a different registry again. The `_ext_gen` suffix keeps the
new pair in the naming family they belong to (`key_share_ext_gen`,
`psk_ext_gen`), and away from those two.

## 6. What is deliberately not asked for

**Parsing an RPK `Certificate` message.** RFC 7250 s:3 replaces the certificate
chain with a bare `SubjectPublicKeyInfo`, and neither tlslite nor tlsfuzzer
parses that. Implementing it would mean putting `ExtensionType` members and a
Certificate parser into tlsfuzzer, one layer below where they belong, and that is
the competing-copy problem this whole document exists to avoid - only pointed at
tlslite instead of at Penzzer.

The right home is **tlslite-ng upstream**, and upstream's own "fix these
constants" comment suggests they would take it. Until then the Penzzer module
stops at the ServerHello, which is far enough: a peer that cannot choose its
credential never gets that far.

So this ask covers the **sending** half only. That is the half the test case
needs.

## 7. Acceptance

[`rpk_acceptance.py`](rpk_acceptance.py) in this directory. Checks 1 to 5 need
no network and no peer:

```
venv/bin/python3 docs/rpk/rpk_acceptance.py
```

It asserts the extension type numbers, both body encodings, the length guard,
and that a generated ClientHello carries extension 20 with the right bytes. It
exits non-zero and names what failed. Before the change it fails at check 1,
naming the two missing generators and pointing at section 5; after it, all
checks pass. It puts the repository root on `sys.path` itself, so it runs from
any working directory without `PYTHONPATH`.

Check 6 is live and is skipped unless a peer is up:

```
openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -subj /CN=localhost -days 1
openssl s_server -accept 44330 -cert c.pem -key k.pem -enable_server_rpk -tls1_3
venv/bin/python3 docs/rpk/rpk_acceptance.py --peer 127.0.0.1:44330
```

That proves a real RPK-capable server accepts the solicitation. It does **not**
reproduce CVE-2026-14457, which additionally needs a server holding a private key
with no certificate - a configuration `s_server` cannot express, since `-nocert`
drops the key along with the certificate. Reproducing it needs a purpose-built
server calling `SSL_CTX_use_PrivateKey()` and not `SSL_CTX_use_certificate()`.
Not built, and not required for this ask.

## 8. Sequencing

Penzzer cannot land its side until the fork change ships and `requirements.txt`
moves to a commit carrying it, or the module's import fails. So the fork goes
first.

**Nothing else is in the way.** An earlier draft of this section reported the
venv broken - `AttributeError: type object 'SignatureScheme' has no attribute
'mldsa87'` at import of `tlsfuzzer.runner`, from `helpers.py` line 96 meeting an
installed tlslite-ng 0.8.2. That was an environment that had drifted from the
pin, not a repository problem. `requirements.txt` pins `tlslite-ng==0.9.0b2`,
which defines `mldsa87 = (9, 6)`; installing it makes `tlsfuzzer.runner` import
and the full unit suite pass (1015 tests, 0 failures, verified 2026-08-27). No
pin needs to move.
