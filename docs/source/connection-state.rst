================
Connection state
================

Processing of nodes like :py:class:`~tlsfuzzer.expect.ExpectServerHello`
or :py:class:`~tlsfuzzer.messages.ClientKeyExchangeGenerator` updates the
state of the connection: the encryption keys, handshake hashes, and so on.

To perform more complex handshakes, you need to take more direct control
of some of those variables.

Opening and closing the connection
==================================

To open a :term:`TCP`: connection use the
:py:class:`~tlsfuzzer.messages.Connect` node.
It provides also ability to control the record layer protocol version
using the ``version`` parameter and setting the amount of time runner waits
for messages from peer using the ``timeout`` parameter.

In contrast, the :py:class:`~tlsfuzzer.messages.Close` node closes the
:term:`TCP` connection and doesn't accept any parameters.

For example, to start session resumption, you need to close the old connection
and open a new one.

You can find a usage example of them in:
`test-tls13-session-resumption.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/scripts/test-tls13-session-resumption.py>`_.


Handshake hashes
================

:term:`TLS` uses a running hash of all exchanged messages to verify the
integrity of the handshake and to perform signatures in CertificateVerify
messages.

Before session resumption or renegotiation, you need to zero out, or reset,
those hashes.

The :py:class:`tlsfuzzer.messages.ResetHandshakeHashes` node allows to do that.

For example, to start renegotiation right after finishing a handshake use
the following code:

.. code:: python

    node = node.add_child(ExpectChangeCipherSpec())
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ClientHelloGenerator(ciphers,
                                               session_id=bytearray(0),
                                               extensions=ext))

You can find a usage example in:
`test-legacy-renegotiation.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/scripts/test-legacy-renegotiation.py>`_.

Renegotiation info
==================

During secure renegotiation peers send the value of last Finished message
in the ``renegotiation_info`` extension.
If you use automatic generators for processing this extension, you
need to reset the values from Finished before a new handshake
using :py:class:`~tlsfuzzer.messages.ResetRenegotiationInfo`.

For example, to start session resumption using session IDs use the following
code:

.. code:: python

    ...
    node = node.add_child(ExpectClose())
    node = node.add_child(Close())
    node = node.add_child(Connect(host, port))
    node = node.add_child(ResetHandshakeHashes())
    node = node.add_child(ResetRenegotiationInfo())
    node = node.add_child(ClientHelloGenerator(
        ciphers,
        extensions={ExtensionType.renegotiation_info:None}))

You can find a usage example in:
`test-sessionID-resumption.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/scripts/test-sessionID-resumption.py>`_.

.. _clearing-encryption-settings:

Clearing encryption settings
============================

Tlsfuzzer allows also disabling encryption for sent messages.
To reset the context for sending records, use the
:py:class:`~tlsfuzzer.messages.ResetWriteConnectionState`.

For example, to send an unencrypted Finished message use the following code:

.. code:: python

    ...
    node = node.add_child(ExpectFinished())
    node = node.add_child(ResetWriteConnectionState())
    node = node.add_child(FinishedGenerator())

You can find a usage example in
`test-tls13-finished-plaintext.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/scripts/test-tls13-finished-plaintext.py>`_.

Clearing post-handshake authentication context
==============================================

A client associates its reply to the server's CertificateRequest message
by sending it with the same context.
To pass that association around
:py:class:`~tlsfuzzer.expect.ExpectCertificateRequest`,
:py:class:`~tlsfuzzer.messages.CertificateGenerator`,
:py:class:`~tlsfuzzer.messages.CertificateVerifyGenerator`,
and :py:class:`~tlsfuzzer.messages.FinishedGenerator` accept the ``context``
keyword argument.
If the runner executes the same conversation many times, as it does with
``sanity`` test cases, that context needs resetting between runs.
:py:class:`~tlsfuzzer.messages.ClearContext` provides this functionality.

For example, to handle a single post-handshake authentication use the
following code:

.. code:: python

    ...
    context = []
    node = node.add_child(ExpectCertificateRequest(context=context))
    node = node.add_child(CertificateGenerator(
        X509CertChain([cert]), context=context))
    node = node.add_child(CertificateVerifyGenerator(
        private_key, context=context))
    node = node.add_child(FinishedGenerator(context=context))
    node = node.add_child(ClearContext(context))

You can find a usage example in
`test-tls13-post-handshake-auth.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/scripts/test-tls13-post-handshake-auth.py>`_.
