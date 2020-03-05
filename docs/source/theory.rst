======
Theory
======

By cooperating with each other, the record layer protocol, the handshake
protocol, the alert protocol, and the application data protocol create
the :term:`TLS` protocol.

By working together, they establish a connection that provides an
integrity-protected tunnel or socket. The connection, if negotiated, also
include authentication of server, or both server and client. Most connections
also provide encryption of the data travelling in the tunnel.

By modifying the messages sent, tester can check if the other side
establishes the connection in expected circumstances. Tester can also check
if an implementation aborts the connection on protocol violations, use
of unimplemented, or turned off features. Same for the integrity,
authentication, and encryption, by modifying the data sent, tester can verify
if the other side implements the checks necessary to provide these properties.

:term:`TLS` protocols
=====================

The record layer protocol provides the multiplexing capability to
exchange the data from the other :term:`TLS` protocols over the same
TCP connection or socket.

Record layer
------------

The record layer protocol uses records to transfer data belonging to a given
upper level protocol.
It provides a stream abstraction, just like a TCP connection.
That means, the upper layer protocols can't depend on writes generating
a particular number or size of records.
The record layer can combine messages into a single
record with other data of the same higher level protocol.

In particular, a record can have at most :math:`2^{14}` bytes of payload.
To process bigger messages from higher level protocols (e.g. ClientHello)
record layer fragments them and sends them in more than one record.

By extending the payload with the protocol type and size of the payload,
the record layer provides multiplexing to the higher level protocols.

Record layer protects the integrity of exchanged data and, optionally,
encrypts and decrypts data.
It uses keys and ciphers negotiated by the
handshake protocol to do that.

Handshake protocol
------------------
Handshake protocol establishes the keys used in the
connection and, optionally, the identities of the server or
server and client.

Similarly to record layer, handshake protocol messages also include the
payload type and payload size.

Unlike the record layer, handshake protocol limits the size of messages
to :math:`2^{24}-1` bytes.
Handshake protocol also forbids fragmenting or combining of the messages.

Application data protocol
-------------------------

Application data protocol encapsulates the data provided to :term:`TLS`
so that it can travel in the same connection as messages internal to
:term:`TLS`. It serves as a content type to the record layer protocol.

But just like other protocols travelling over record layer, it can't depend
on specific fragmentation of writes to the other side.

Alert protocol
--------------

Alert protocol provides signalling of error conditions or unmet expectations
to the other side of the connection.
When messaging non-fatal errors, in some cases, the connection can continue
even after their exchange.

An alert message consists of two bytes.

Testing process
=================

The basic testing scenarios focus on the so called "happy path":
verifying that everything works when nothing unexpected occurred.
While testing for support of features needs to
use this kind of approach, negative test cases must use malformed or
unexpected messages, especially in security protocols.
Correct handling of unexpected situations provides the security.

The :term:`TLS` specification requires strict verification of message
format from the parsers.
It also describes precisely the expected contents of majority of exchanged
fields—encryption or integrity protection of messages allows for one
valid and correct formatting of messages or records, for a given set of
keys.
The specification includes also information on error handling,
it describes the expected alert messages for given error conditions.

This allows the tests to send either malformed or inconsistent messages and
check for specified alerts to verify if the other side of the connection
performed the expected error checking.

.. note::
   Fuzzers generally don't operate in this way.
   Typical fuzzers
   feed the system under test (:term:`SUT`) with lots of random or semi-random
   inputs and check if the :term:`SUT` doesn't crash, use uninitialised memory
   or invokes some other undefined behaviour. While tlsfuzzer can generate this
   kind of tests, included scripts don't do it—they
   focus on checking if the server behaves as expected, even when they use
   random data for it.

.. _checking-alerts:

Checking alerts
---------------

Given that the guiding RFCs allow for *not* sending the alerts at all, one
could argue that checking both reception of alerts and
the included error codes in them to be undue carefulness.

Actually though exploitation of security vulnerabilities thanks to
the different error codes returned for different errors detected
has a long history.
When returned errors depend on secret data, unknown to attacker, that may lead
to decryption oracles or other side-channel attacks.
The standards do take this into account, which makes standard-compliant
behaviour the "known good" behaviour.

Consistent and standards-compliant errors also make debugging of
interoperability issues easier.
Alert description points to the reason of rejection: a certificate issue,
a malformed message, a message inconsistent with other messages, etc.

Consistent and correct alerts also allow pushing those errors higher in
the stack—if user-level application can depend on particular meaning of
errors it can provide more correct and relevant errors to the user.

To confidently test for security vulnerabilities across different
implementations, the implementations must behave in consistent, or at least
similar ways.
When they do, tlsfuzzer can reuse a single verification script to test
them.

When test doesn't have an easy insight into the process serving :term:`TLS`,
getting the alert instead of connection close allows for at least basic
verification if the :term:`SUT` didn't crash but handled the error.

Sharing of general test suites has the same limitations as sharing of security
test scripts.
If different implementations exhibit the same behaviour, they can share the
same test suite, in turn reducing effort necessary to develop new
implementations or extend existing implementations with new features.

Last, but not least, particular way of handling errors provides a strong signal
for fingerprinting (identifying) the implementation used.
As alert descriptions returned by an implementation don't depend on
implementation configuration, the fingerprints don't either, making them
robust—hard to masquerade one implementation for another
(with some exceptions, like in case the server doesn't parse extensions from
turned-off features).
