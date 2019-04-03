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


def curve_name_to_hash_tls13(curve_name):
    """Find the matching hash given the curve name, as specified in TLS 1.3."""
    if curve_name == "NIST256p":
        return "sha256"
    if curve_name == "NIST384p":
        return "sha384"
    if curve_name == "NIST521p":
        return "sha512"
    raise ValueError("Curve {0} is not allowed in TLS 1.3 "
                     "(wrong name? please use python-ecdsa names)"
                     .format(curve_name))
