# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Methods for dealing with TLS Handshake protocol"""

def calc_pending_states(state):
    """Calculate state for pending encryption values in TLS socket"""
    state.msg_sock.calcPendingStates(state.cipher,
                                     state.key['master_secret'],
                                     state.client_random,
                                     state.server_random,
                                     None)
