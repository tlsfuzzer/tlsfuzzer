==============================
Writing test coverage for RFCs
==============================

As :term:`TLS` has long history and offers support for multiple algorithms,
features often interact with each-other.
When planning test coverage for a new feature or a new extension, you need
to create test cases for those possible interactions.

The standard
============

To create a good test coverage you need to have detailed standard—one that
includes expected behaviour both for expected and unexpected behaviour from
the peer.

See text below for detailed list of possible interactions.

To ensure that the standard is detailed enough you should get involved with it
at the draft stage and check if it includes things like expected alert
descriptions or iteractions with session resumption.
:term:`IETF` doesn't allow changes to already published :term:`RFC`\ s.

Planning test coverage
======================

You should read the standard and annotate it in places where it prescribes
specific behaviour.
Then turn those annotations into test scripts or test cases.

The list of cases to consider for inclusion in a script:

..
    The following list has external references to it, please don't renumber it

1. **sanity check**: simple configuration to check if connection with server
   works and that server continues to work after all tests are finished
2. **specific alert**: when testing for error conditions, the ExpectAlert
   expects one specific value for the alert (with one exception, instead of
   ``handshake_failure`` server may send ``insufficient_security``); test
   needs to fail if the server doesn't send an alert (with the exception of
   ``close_notify`` alert)
3. **renegotiation**: check how feature interacts with renegotiation, do
   renegotiation handshakes need to include it, can it use different settings
   in it, can the client omit it? (only for :term:`TLS` 1.2 and earlier)
4. **resumption**: check how feature interacts with session resumption, do
   clients have to advertise it in the resumed client hello, does the server
   need to advertise it in resumed session, can it use different settings in
   resumed session? Can clients drop it in resumed session?
5. **client certificates**: does the feature relates to handling certificates,
   does the client need to send it too when the server asked for it in the
   extensions of CertificateRequest (:term:`TLS` 1.3)?
6. **virtual hosts**: does the standard permin for different behaviour for
   different virtual hosts, either defined by different
   :term:`SNI`/``server_name`` or by :term:`ALPN`? If not explicitly allowed,
   do you test for consistent behaviour?
7. **undefined codepoints**: does the standard describe behaviour with
   undefined code points (see for example at ``signature_algorithms``
   extension), does the peer has to ignore them? What happens if the
   connection has only undefined (essentially unknown to the peer) points?

   * use the undefined code points first then place well known in the
     list—after all if new types are added, they should be more secure than
     the old types—to verify that peer doesn't have hardcoded limits for
     list lengths
8. **disabled codepoints**: do the disabled codepoints not cause issues when
   they are advertised together with the good codepoints (e.g. MD5 hashes in
   ``signature_algorithms``, Koblitz curves in ``supported_groups`` in
   :term:`TLS` 1.3)?
9. **duplicated codepoints**: does the standard allow for duplicated entries
   (items with the same values)? If not, does the peer reject them? What
   happens if script sends a lot of duplicated, known, but unsupported (or
   disabled) entries before sending something that the server accepts?
   (this checks if peer does not abort parsing after filling a short list of
   known values)

   .. note::
       unless a definition for a particular list doesn't prohibit duplicated
       values (like for ``key_shares`` or extensions as a whole),
       :term:`TLS` *does* allow for duplicated values

10. **invalid combinations**: check if peer doesn't accept different codepoints
    in place of a correct one, like a RSA signature with a RSA certificate but
    advertised as an ECDSA signature, or a ``ecdsa_secp521r1_sha512``
    signature with a secp256r1 certificate in :term:`TLS` 1.3 (to verify that
    the peer checks the whole value and doesn't short-circuit some checks)
11. **large lists**: check if the server can process a list that has max size
    but is otherwise well-formed (check if server doesn't have inherent limits
    for processing)
12. **empty values**: many arrays in :term:`TLS` have min length greater than
    zero, check if peer rejects empty values in such cases
13. :term:`PRF` **interaction**: for features that depend on master secret
    calculation, do they work as expected with ciphers that use
    "protocol default :term:`PRF`" (:term:`TLS` 1.1 ciphers in :term:`TLS`
    1.2), SHA-256, or SHA-384 as :term:`PRF`?
14. **padded/truncated lengths**: do you check if values like extension
    payloads or array elements are not accepted when they have less data than
    expected or more data than they should (i.e. mismatch between different
    length fields)
15. **padded/truncated data**: for fields like signatures or finished values,
    the data needs to be of very specific size, check if it is padded or
    truncated (either left or right, both for padding and truncation, or
    completely omitted, length included), it is rejected
16. **impossible lengths**: for lists of same sized items, some sizes are
    impossible, like odd lengths for ClientHello cipher list or
    ``signature_algorithms`` list of schemes, check if peer rejects this kind
    of values (including one-byte payload)
17. **HelloRetryRequest interaction**: for extensions sent in ClientHello that
    affect :term:`TLS` 1.3 sessions, verify if server detects a modified
    version of it in 2nd ClientHello and aborts the connection

    * also check if server detects adding of it to 2nd ClientHello or dropping
      of it from 2nd CH and aborts the connection
18. **TLS 1.3 padding**: if the extension affects handling of records, how does
    it interact with TLS 1.3 record layer padding? do the size limits apply to
    padding or not?
19. **0-RTT**: does it impact handling of ``early_data`` messages?
20. **version confusion**: does the peer reject values or messages valid in one
    version of protocol when test uses them in another?
    (e.g. it needs to reject ``rsa_pkcs1_sha224`` signatures in :term:`TLS`
    1.3 and KeyUpdate messages in :term:`TLS` 1.2)
21. **documentation**: does the script describe (in *printed* messages) what
    is the general purpose of it?
22. **version**: does the script report its version? (you should make it a
    monotonically increasing value, updated with every change to the test
    scenarios)
23. **protocol version/protocol type**: does protocol version of :term:`TLS`
    have an impact? is it applicable to :term:`DTLS`?
    (tlsfuzzer doesn't support :term:`DTLS`, yet: `#55
    <https://github.com/tomato42/tlsfuzzer/issues/55>`_)
24. **interaction with other extensions**: does the test need to test the
    scenario also with other extensions?

    1. ``extended_master_secret``: deos the scenario interact with derived
       secrets of keys?
    2. ``encrypt_then_mac`` (EtM): does the scenario interact with record
       layer? record sizes? ciphers?
25. **renegotiation and resumption**: how does the extension behave when the
    renegotiation *and* resumption is combined, especially when the resumed
    session had the status of extension different than the session in which
    the renegotiation happens? See also points 3. and 4. (no support for such
    test cases, see `#591
    <https://github.com/tomato42/tlsfuzzer/issues/591>`_)
26. **invalid extension for message**: RFC 8446 Section 4.2 states that
    peers must reject recognised extensions in unexpected messages (like
    ``cookie`` in CertificateRequest) with ``illegal_parameter``. Verify that
    peer behaves in this way.
