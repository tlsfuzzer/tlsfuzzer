====================
Statistical analysis
====================

As cryptographic security depends on proper use of primitives, tests
need to verify contents of parameters.

Tlsfuzzer allows collecting some of the parameters to perform the analysis
later.

AES-GCM nonces
==============

The :term:`AES-GCM` construction in :term:`TLS` 1.2 uses explicit nonces.
Peers select the nonce themselves and send it to their peer.

Since reusing the nonce breaks the encryption, the peers must not do that.

To collect the nonces sent by peer, use the
:py:class:`~tlsfuzzer.messages.CollectNonces` node.
Place it right after encryption negotiation: after
:py:class:`~tlsfuzzer.expect.ExpectChangeCipherSpec` node.

After executing the connection through runner, the passed in array has
the nonces selected by the peer saved as binary strings—one for every record
received.

See the
`test-aes-gcm-nonces.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-aes-gcm-nonces.py>`_
script for example how to verify that they monotonically increase.

Saving cryptographic parameters
===============================

Unlike nonces, negotiation or advertising of other cryptographic parameters
happens just once per connection.
To save those parameters use the
:py:class:`~tlsfuzzer.messages.CopyVariables` node.
For full list of supported parameters see the class documentation,
you can find definitions of the names in the :term:`TLS` :term:`RFC`\ s.

As a parameter this node accepts a dictionary in which keys specify names of
parameters to collect. The node appends collected parameters to the values
of the dictionary.

For example, to check the uniqueness of ``random`` values sent in
``ServerHello``, use the following code:

.. code:: python

    collected_randoms = []
    variables_check = {"ServerHello.random": collected_randoms}
    conversation = Connect(host, port)
    node = conversation
    ciphers = [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
               CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
    node = node.add_child(ClientHelloGenerator(ciphers))
    node = node.add_child(ExpectServerHello())
    node = node.add_child(CopyVariables(variables_check))
    node = node.add_child(Close())

    runner = Runner(conversation)
    runner.run()
    runner = Runner(conversation)
    runner.run()
    assert collected_randoms[0] != collected_randoms[1]

You can use the same ``variables_check`` or ``collected_randoms`` with more
than one :py:class:`~tlsfuzzer.messages.CopyVariables`, it appends new
values to the arrays, it doesn't replace the arrays.

You can find a usage example of it in:
`test-serverhello-random.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-serverhello-random.py>`_.

.. tip::

    Tlsfuzzer provides a simple function to verify uniqueness of parameters in
    such a dictionary: :py:func:`~tlsfuzzer.helpers.uniqueness_check`.
