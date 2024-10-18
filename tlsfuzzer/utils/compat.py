# Author: George Pantelakis, (c) 2024
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Miscellaneous functions to mask Python version differences."""

import sys


def bit_count(number):
    """Counts the bits of an integer"""
    if sys.version_info >= (3, 10):
        return number.bit_count()
    return bin(number).count("1")
