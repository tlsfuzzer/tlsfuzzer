# Author: Hubert Kario, (c) 2016
# Released under Gnu GPL v2.0, see LICENSE file for details
"""Methods for dealing with TLS Handshake protocol"""


from tlslite.keyexchange import FFDHKeyExchange, ECDHKeyExchange
from tlslite.constants import GroupName


def calc_pending_states(state):
    """Calculate state for pending encryption values in TLS socket"""
    state.msg_sock.calcPendingStates(state.cipher,
                                     state.key['master_secret'],
                                     state.client_random,
                                     state.server_random,
                                     None)


def kex_for_group(group, version=(3, 4)):
    """Get a KeyExchange object for a given group and protocol version."""
    if group in GroupName.allFF:
        return FFDHKeyExchange(group, version)
    return ECDHKeyExchange(group, version)
