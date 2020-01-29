# Author: Hubert Kario
# Copyright 2018(c) Red Hat
# see LICENCE file for licensing information
"""Classes used for generating random (fuzzing) data"""

import random


class StructuredRandom(object):
    """Random data with structure.

    This class allows easy creation of random data that is structured,
    either by having a random bytes of specific length, or intermediate bytes
    that are constant.

    vals is a list of tuples, the first element in the tuple specifies the
    length of the run and the second specifies the values of the bytes
    in the run. If the value is None, it means the bytes should be random.

    thus a ``vals = [(16, 0)]`` will create a bytestring of length 16, with
    all bytes equal to zero and ``vals = [(4, None), (5, 6)]`` will create
    a bytestring that has 4 random bytes followed by 5 bytes of value 0x06.
    """
    def __init__(self, vals, rng=None):
        """Init the Object.

        :param rng: the random number generator to use, `random` by default
        """
        self.vals = vals
        if not rng:
            rng = random
        self.rng = rng

    @property
    def data(self):
        """Generate the random string based on description in vals."""
        ret = bytearray()
        for length, content in self.vals:
            if content is None:
                ret += bytearray(self.rng.randint(0, 255)
                                 for _ in range(length))
            else:
                ret += bytearray([content] * length)
        return ret

    def __repr__(self):
        """Human readable description of the object."""
        return "StructuredRandom(vals={0})"\
               .format(self.vals)


def _normalise_groups(groups, sum_len, step):
    """Make sure the sum of all lengths in groups is a multiple of step."""
    if sum_len % step:
        for i, val in enumerate(groups):
            if val[0] > (sum_len % step):
                groups[i] = (val[0] - (sum_len % step), val[1])
                sum_len -= sum_len % step
                break

    # in case the list or all elements are super short
    if sum_len % step:
        groups[0] = (groups[0][0] + step - (sum_len % step),
                     groups[0][1])
        return


def _pick_length(rng, group_min, group_max):
    """Pick lengths of byte runs."""
    # generate short elements sometimes
    if rng.choice([True, False]):
        length = rng.randint(group_min, group_max)
    else:
        length = rng.randint(group_min,
                             max(group_min, group_max // 10))
    return length


def _pick_run_type(rng, length):
    """Pick the payload of the runs with specified size."""
    # generate different looking strings
    if rng.choice([True, False, False, False]):
        return (length, None)
    elif rng.choice([True, False, False]) and length < 256:
        return (length, length - 1)

    return (length, rng.randint(0, 255))


def structured_random_iter(count=100, min_length=1, max_length=2**16, step=1):
    """
    Iterator that returns a random StructuredRandom object.

    Useful as a payload for TLS message plaintext
    """
    rng = random.SystemRandom()
    max_length = rng.randint(min_length, max_length)
    for _ in range(count):
        # select usually a small number of groups and clamp it to the
        # maximum length of data (as we don't generate 0-length groups)
        no_groups = int(rng.gammavariate(2, 2)) + 1
        no_groups = min(max_length, no_groups)

        groups = []
        sum_len = 0
        for i in range(no_groups):
            group_min = 1
            group_max = max_length - sum_len - (no_groups - i - 1)
            length = _pick_length(rng, group_min, group_max)
            groups.append(_pick_run_type(rng, length))
            sum_len += length

        _normalise_groups(groups, sum_len, step)

        yield StructuredRandom(groups)
