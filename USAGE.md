While `tlsfuzzer` is currently more of a framework than a full-featured tool,
it still is possible to run tests against common server configurations with a
little bit of effort.

Simple workflow
===============

Preparation
-----------

To run the scripts you will need 3 libraries:

 * [six](https://github.com/benjaminp/six) ([PyPI](https://pypi.python.org/pypi/six))
 * [ecdsa](https://github.com/warner/python-ecdsa) ([PyPI](https://pypi.python.org/pypi/ecdsa))
 * [tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng) ([PyPI](https://pypi.python.org/pypi/tlslite-ng))

It's common that `six` is already installed, or is available from the operating
system repository.

Alternatively it can be installed by running `pip install six` as root.

The other two can be installed (again, using `pip install ecdsa` and
`pip install tlslite-ng`) or they all can be downloaded to a single location to
minimise dependence on root privileges and permanent changes to the system. For
the rest of this tutorial, I'll follow the latter approach.

**Note:** the above libraries and `tlsfuzzer` support both Python 2 and Python
3, but they require at least Python 2.6. If you are running a modern
distribution (RHEL 6 or later), using the provided `python` in the below
commands is sufficient, if you're running older distribution, you will need to
install new python, and use it for the below commands, usually switching
`python` to `python26` (or similar).


In other words, if you have `six` already installed, the environment can be
prepared by running the following commands:
```
git clone https://github.com/tlsfuzzer/tlsfuzzer.git
cd tlsfuzzer
git clone https://github.com/warner/python-ecdsa .python-ecdsa
ln -s .python-ecdsa/src/ecdsa/ ecdsa
git clone https://github.com/tlsfuzzer/tlslite-ng .tlslite-ng
ln -s .tlslite-ng/tlslite/ tlslite

```

Running tests
=============

When all dependencies are downloaded or installed, place yourself in the root
directory of the project (one with `tlsfuzzer`, `tests` and `scripts`
directories) and you can start running tests.

All tests support a minimum set of parameters:

 * `-h` to specify the hostname of the server under test (tests usually
   default to `localhost`)
 * `-p` to specify the port of the server under tests (tests default to 4433)
 * `--help` to display all options supported by a given script
 * names of the scenarios that are to be run (if not provided, all tests in a
   script are run)

so to test if a server running on `example.com` on port 433 is not vulnerable
to the
[Bleichenbacher attack](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf),
you need to run the following command:

```
PYTHONPATH=. python scripts/test-bleichenbacher-workaround.py -h  example.com -p 443
```

A run of it will look something like this:
```
(beginning omitted)
zero byte in last byte of random padding ...
OK

zero byte in first byte of random padding ...
OK

Test end
successful: 8
failed: 0
```

That prints the names of tests being run (e.g. "zero byte in first byte of
random padding") and the overall test result, that 8 tests were run and the
server behaved as expected, and in 0 situations the test failed.

**Note**: unless stated otherwise in the help message of a specific test case,
the scripts usually expect a HTTP server with no client certificate
authentication.

In such case (where there were no errors), that usually ends the testing and
identifies the server as following the relevant RFC documents (like
[RFC 5246](https://tools.ietf.org/html/rfc5246)) or not vulnerable to the
vulnerability.

Investigating errors
====================

Theory of operation
-------------------

To be able to read the error messages of `tlsfuzzer` scripts, it's necessary to
know a little about how it works internally.

The simplest test script is the
[test-conversation.py](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-conversation.py),
in it you will find a lot of boilerplate, and a single test scenario:
```
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
```
What this code does, is it sets up a list of things to do and things to expect
from the server. In this case, it performs a simple
[RSA key exchange](https://tools.ietf.org/html/rfc5246#page-36), an HTTP GET
request and expects data back.

Nodes with `Generator` in the name are creating messages and sending them to
the server, nodes that have `Expect` in the name will pause execution (with a
timeout) and wait for a message from the server.

In some cases, multiple behaviours are acceptable, this is implemented using
the "siblings". In the above example, after sending the `close_notify` Alert to
server, the test case expects the server to either send an alert of its own
(`ExpectAlert`), *or* to just close the connection (`ExpectClose`).

If a node has no children, an implicit (TCP) connection close is placed there.

Expect nodes not only verify that the messages received match the expected
type, but also that it is matching other messages (e.g. that the Server Hello
doesn't advertise support for extensions that the Client Hello didn't include).
In other words, unless there are specific options set, tlsfuzzer will behave as
a strict, well-behaved TLS client.

General note
------------

Scripts expect specific *behaviour* from a server, not specific error or
message.

In other words, a *passing* test is a test to which the behaviour of the server
matched the expectation (in some cases that may mean that server did report a
failure through Alert message). A *failing* test is a test in which the server
did not match expected behaviour - for example did not detect an error it
should have detected and continued handshake.


Reading error messages
----------------------
Typical error message looks like this:
```
zero byte in first byte of random padding ...
Error encountered while processing node <tlsfuzzer.expect.ExpectAlert object at 0x7f96e7e56a90> (child: <tlsfuzzer.expect.ExpectClose object at 0x7f96e7e56ad0>) with last message being: <tlslite.messages.Message object at 0x7f96e79f4090>
Error while processing
Traceback (most recent call last):
  File "scripts/test-bleichenbacher-workaround.py", line 250, in main
    runner.run()
  File "/root/tlsfuzzer/tlsfuzzer/runner.py", line 178, in run
    node.process(self.state, msg)
  File "/root/tlsfuzzer/tlsfuzzer/expect.py", line 571, in process
    raise AssertionError(problem_desc)
AssertionError: Expected alert description "bad_record_mac" does not match received "handshake_failure"
```

The first line, informs us which scenario was running when the error occurred,
in this case "zero byte in first byte of random padding".

Second line tells us which node was being processed, in this case it was
`ExpectAlert` and its child is `ExpectClose`.

Finally, the last line tells us what went wrong, in this case the error was
that the test expected an alert with `bad_record_mac` but got
`handshake_failure`.

### Common errors

#### Alert description mismatch

Pattern:
```
Error encountered while processing node <tlsfuzzer.expect.ExpectAlert ...
...
AssertionError: Expected alert description "bad_record_mac" does not match received "handshake_failure"
```

Situations where the received alert does not match the expected one may be
sign of a vulnerability (like in the example with Bleichenbacher test above),
bug in implementation under test or RFC non-compliance. In *rare* cases it may
be caused by test case being too strict (e.g. in some situations sending
`insufficient_security` alert when the test expects `handshake_failure` is
valid behaviour).

#### Unexpected message - Alert
Pattern:
```
`Error encountered while processing node <tlsfuzzer.expect.ExpectServerHello ...
...
AssertionError: Unexpected message from peer: Alert(fatal, handshake_failure)``

```

`handshake_failure` alert received in place of Server Hello usually means that
the server did not accept any cipher or any extension settings we sent to it.
This may happen when the server has only an ECDSA certificate (support for them
is not advertised in many scripts in in tlsfuzzer)
or did not enable ciphers which are necessary for the test being run.

Most tests require TLS_RSA_WITH_AES_128_CBC_SHA cipher to be enabled. In cases
where the test checks handling of messages not applicable in RSA key exchange,
the ciphers used are other variants of the AES ciphersuites. Inspect specific
script to know more or read its help message.

#### Unexpected message - Certificate Request
Pattern:
```
Error encountered while processing node <tlsfuzzer.expect.ExpectServerHelloDone
...
AssertionError: Unexpected message from peer: Handshake(certificate_request)
```

Situation like this means that the server asked the client for certificate (did
send Certificate Request message) but the client (tlsfuzzer) did not expect
that. In cases like this either the server should be reconfigured to not ask
for client authentication, or a different test script should be used.

#### Unexpected message - Application Data
Pattern:
```
Error encountered while processing node <tlsfuzzer.expect.ExpectAlert ...
...
AssertionError: Unexpected message from peer: ApplicationData(len=8000)
```

**Note**: for most tests it will be `ExpectAlert`, but in general, we're
looking for a node right *after* `ExpectApplicationData`.

Test cases in general expect just one TLS record as a response to the HTTP GET
query. That limits the response to 16384 bytes (16kiB).

Situations where it is OK to send more than one Application Data message:

 * when the response is larger than 16KiB
 * when the server is optimised for latency
   ([Time to first byte](https://en.wikipedia.org/wiki/Time_to_first_byte)) and
   **all** messages but the last have the same size (e.g. 4KiB, 4KiB, 4KiB and
   277B would be OK)
 * when the negotiated protocol is TLS 1.0 and the negotiated cipher suite is
   using CBC mode, then the first message can be 1 or 0 bytes long, and others
   just as above (this is mitigation of the
   [BEAST](https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack))
 * the server under test is an echo server, not HTTP, then it may send two
   Application Data packets as it will receive two lines as the input

Unfortunately that complexity means that the analysis needs to be performed
manually, using a tool like [Wireshark](https://www.wireshark.org/).

Some situations where multiple Application Data messages being sent is not ok:

 * splits happening on line end - that leaks the line lengths to a passive
   observer
 * splits happening on HTTP headers end - that leaks the size of headers to a
   passive observer
 * 1/n-1 split in TLS 1.1 or later or in stream ciphers - it's unnecessary and
   wastes bandwidth

#### Required extension
Pattern:
```
Error encountered while processing node <tlsfuzzer.expect.ExpectServerHello ...
...
AssertionError: Required extension renegotiation_info missing
```

**Note**: the specific extension depends on test case.

Error of this kind usually means that the server does not support functionality
necessary for the test or, in case of `renegotiation_info` does not support a
feature that many other servers consider mandatory.

#### Unrecognized AlgorithmIdentifier
Pattern:
```
Error encountered while processing node <tlsfuzzer.expect.ExpectCertificate ...
...
  File "/home/hkario/dev/tlsfuzzer/tlslite/messages.py", line 1128, in _parse_tls12
    x509.parseBinary(certBytes)
  File "/home/hkario/dev/tlsfuzzer/tlslite/x509.py", line 92, in parseBinary
    raise SyntaxError("Unrecognized AlgorithmIdentifier")
SyntaxError: Unrecognized AlgorithmIdentifier
```

This is an indication that the server has sent a certificate with an DSA or
EdDSA key. They are currently unsupported in `tlsfuzzer` or `tlslite-ng`.
Reconfigure the server to use RSA or ECDSA certificates.

If a server already is configured with ECDSA or RSA certificates, it indicates
that the system for selecting correct certificate (or certificate chain) when
the client does not adverise support for given key type is not working
correctly.

#### Connection refused or timeout in Connect
Pattern:
```
Error encountered while processing node <tlsfuzzer.messages.Connect ...
...
    sock.connect((self.hostname, self.port))
  File "/usr/lib64/python2.7/socket.py", line 228, in meth
    return getattr(self._sock,name)(*args)
error: [Errno 111] Connection refused
```
and
```
Error encountered while processing node <tlsfuzzer.messages.Connect...
...
  File "/usr/lib64/python2.7/socket.py", line 228, in meth
    return getattr(self._sock,name)(*args)
timeout: timed out
```

The hostname or the port are incorrect for the system or a firewall on the way
blocks communication.

In other words: communication failed before TLS got involved.


#### Unexpected closure from peer
Pattern:
```
Error encountered while processing node <tlsfuzzer.expect.ExpectServerHello ...
...
AssertionError: Unexpected closure from peer
```

**Note**: it may happen at any node, though most commonly on
`ExpectServerHello` and `ExpectAlert`.

Some TLS implementations (or some combinations of TLS implementation and an
application) do not send alerts. This makes testing such implementations much
harder, and verifying that the exchanged messages do not cause unintended
behaviour in the server requires running the tests with valgrind, ubsan, asan
and extended logging on server side. This makes running the tests and verifying
results much harder and specific for that one implementation. Because
`tlsfuzzer` aims to be a universal test suite and RFC conformance checker,
test cases are not written in a way that allows the server to not send alert
messages.

Case in point: if `test-bleichenbacher-workaround.py` would be written in a way
that server can respond either with an alert or by closing the connection, a
vulnerable behaviour in which the server sometimes sends the correct alert and
sometimes closes the connection would *not* be detected, reporting a false
negative to the user.

Test specific notes
===================

`test-bleichenbacher-workaround.py`
-----------------------------------

This test requires a HTTP server with a RSA ciphersuite (`TLS_RSA_WITH_*_*`)
enabled and not asking for client certificates (only for GnuTLS it's not a
default configuration).

In case the server is well-behaved (responds with `handshake_failure` in case
it cannot negotiate the client proposed ciphersuite) and does not support any
RSA ciphersuite `tlslite-ng` supports, *only* the "sanity" tests will fail.
This **does not** mean that the implementation is not vulnerable, only that the
given configuration isn't (assuming that the server does not implement any
uncommon ciphers, like Camellia,  Aria or others unsupported by `tlslite-ng`).

A good test requires a server configuration that enables all RSA ciphers that
a given implementation supports (or, if implementation does not allow for
enabling some groups of ciphers together, multiple runs that together had all
ciphers enabled).

The test is tuned for testing over a WAN link. If the server is on a local
network, it is possible to speed up test execution significantly by passing the
option `-t 0.01` (in general, that number should be twice as big as the RTT to
the server, in seconds). Setting it too low can cause the test case to report
false
negatives!

While the test allows for setting the expected alert response to a Finished
message sent after malformed Client Key Exchange (using the `-a` option) the
alert sent must be the same for all tests (that is, if one half of scenarios
pass with default configuration and other pass with `-a 0` option set, it makes
the server **vulnerable** to the Bleichenbacher attack). In general, the
workaround requires the server *not* to treat the Finished message specially,
so the alert sent *should* be the same as the one generated while running
[test-fuzzed-MAC.py](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-fuzzed-MAC.py).
Also note that if setting this option is necessary, it shows that the server is
not RFC compliant, which in turn, as you can see, makes testing it harder and
more complex.

While not testing for Bleichenbacher directly, the tests
[test-invalid-rsa-key-exchange-messages.py](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-invalid-rsa-key-exchange-messages.py)
and [test-truncating-of-kRSA-client-key-exchange.py](https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-truncating-of-kRSA-client-key-exchange.py)
perform checks related to RSA key exchange. Failures there may be a sign of
other problems.

`test-record-size-limit.py`
---------------------------

This test is very stict on the size of returned reply and expects the reply
to be sent in a single record, if its size allows for that.

To quickly check what is the size that the server sends, it's possible to run
the test with this options:
```
test-record-size-limit.py --reply-AD-size 1 \
'check if server accepts maximum size in TLS 1.2'
```
or:
```
test-record-size-limit.py --reply-AD-size 1 \
'check if server accepts maximum size in TLS 1.3'
```

It should fail with
`AssertionError: ApplicationData of unexpected size: X, expected: 1`
where X is the value that needs to be passed as argument to `--reply-AD-size`.

To make the test case more deterministic, it is possible to specify the
exact (HTTP) request being sent to server using the `--request` option. For
example, to perform a GET request for a specific file, not the `/` object.

`--cookie` option must be used if the server sends `cookie` extension in
HelloRetryRequest message.

`--supported-groups` must to be used when the server sends `supported_groups`
in EncryptedExtension during a normal TLS 1.3 handshakes while
`--hrr-supported-groups` must be used when the server sends that extension
in handshakes that force the server to send HelloRetryRequest message.

In case the server limits the size it advertises in its extension,
then `--expect-size` can be used to set the expected limit. Note though,
the value expected from server in TLS 1.3 will be one byte larger than that for
TLS 1.2 and earlier protocols as this is the expected behaviour of servers that
support the biggest possible records. It also makes the size of actual
application data payload the same irrespective of negotiated protocol version.

`test-tls13-certificate-verify.py`
----------------------------------

This test verifies server's support for different Signature Algorithms for
client certificates and CertificateVerify messages. It tests all the
algorithms supported by tlsfuzzer, and verifies that only the advertised ones
are accepted by the server. It also verifies that algorithms incompatible with
the certificate type provided (e.g rsa_pss_rsae_sha256 with "rsa-pss"
certificates) are refused as well.
It also fuzzes signatures in various ways to make sure servers behave according
to TLS1.3 specifications.

NOTE: To test all algorithms it is necessary to run this test twice, once with
an "rsa" certificate and once with an "rsa-pss" certificate.

The list of server supported Signature Algorithm's must be provided via the -s
command line option, the default is set to match tlslite-ng sigalg selection.
The algorithms can be defined both via shorthand strings, type+hash strings,
type and hash can also be expressed via numeric ids.
Example: `-s "sha256+rsa rsa_pss_pss_sha384 8+11"`

For some correctness tests, only one among multiple algorithms of the same
type will be used. For example there is a test that checks that a "correct"
signature using one hash but being advertised as using different hash is
refused. The test machinery will select a signature algorithm matching the
first hash in an ordered list and use the second hash in the actual signature.
The ordered list of hashes to select from can be changed using the -o
parameter. The default is "sha256 sha384 sha512", in that order.
The test that uses the wrong mgf1 hash, assuming a server that accepts all
standard rsa algorithms, will choose an algorithm that uses the sha256 (the
first in the list) for the envelope, and actually uses sha384 (the second in
the list) for the signature operation.
To test different combinations one can simply change the order to something
like -o "sha512 sha256 sha384"; this will cause the test to send an envelope
for rsa_pss_pss_sha512 (for "rsa-pss" certificates), but will use sha256 as
the actual mgf1 hash when generating the signature.
Other tests also uses the ordered hash list to choose an algorithm among
multiple viable ones advertised by the server and can similarly be affected by
changing the ordered list of hashes.
At least two hashes must be provided in the list, although only one need
to be supported by the server. If a hash is not supported by the server it will
be skipped in test that select algorithms that need to be supported by the
server, skipped hashes may still be selected to generate signatures or invalid
envelope values as needed by the test.
