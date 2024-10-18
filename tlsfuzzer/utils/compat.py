import sys


def bit_count(x):
    """Counts the bits of an integer"""
    if sys.version_info >= (3, 10):
        return x.bit_count()
    return bin(x).count("1")
