"""
Library with tests and fuzzers for the TLS protocol.

Use objects in L{tlsfuzzer.messages} to create objects that will be sent
to the other side of a SSL or TLS connection and L{tlsfuzzer.expect} to process
messages received from the other side. The L{tlsfuzzer.runner} will execute
those prepared messages.

Objects that have direct effect on the state of encryption of the connection:
L{ExpectChangeCipherSpec}, L{ExpectServerHello}, L{ChangeCipherSpecGenerator},
L{ExpectFinished} and L{FinishedGenerator}.
"""
