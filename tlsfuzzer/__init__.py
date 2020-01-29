"""
Library with tests and fuzzers for the TLS protocol.

Use objects in :py:mod:`tlsfuzzer.messages` to create objects that will be
sent to the other side of a SSL or TLS connection and
:py:mod:`tlsfuzzer.expect` to process
messages received from the other side. The :py:mod:`tlsfuzzer.runner` will
execute those prepared messages.

Objects that have direct effect on the state of encryption of the connection:
:py:class:`~tlsfuzzer.expect.ExpectChangeCipherSpec`,
:py:class:`~tlsfuzzer.expect.ExpectServerHello`,
:py:class:`~tlsfuzzer.messages.ChangeCipherSpecGenerator`,
:py:class:`~tlsfuzzer.expect.ExpectFinished` and
:py:class:`~tlsfuzzer.messages.FinishedGenerator`.
"""
