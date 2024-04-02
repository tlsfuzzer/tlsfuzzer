# Author: Hubert Kario
# Released under Gnu GPL v2.0, see LICENCE for details
"""Various statistical methods missing from scipy and numpy."""

import os
from math import sqrt
from itertools import combinations
from collections import defaultdict, namedtuple
from multiprocessing import Pool
from scipy.stats import rankdata, distributions
import numpy as np


def _rank_dict(values):
    """Returns a copy of the dict with values converted to ranks."""
    keys = values.keys()
    ranks = rankdata(list(values.values()))
    return dict(zip(keys, ranks))


skillings_mack_result = namedtuple('skillings_mack_result',
                                   ['p_value', 'T', 'df'])


def _summarise_tuple(current_block, all_groups, adjusted_ranks, block_counts,
                     pair_counts):
    ranks = _rank_dict(current_block)
    len_current_block = len(current_block)
    for pair in (frozenset(x)
                 for x in combinations(ranks.keys(), 2)):
        pair_counts[pair] += 1
    for g in all_groups:
        if g not in ranks:
            ranks[g] = (len_current_block + 1) / 2.0
        else:
            block_counts[g] += (len_current_block - 1)
        adjusted_ranks[g] += sqrt(12/(len_current_block + 1)) * \
            (ranks[g] - (len_current_block + 1) / 2.)


def _set_unique(idx):
    global _groups
    return set(np.unique(_groups[idx[0]:idx[1]]))


def _slices(length, chunksize):
    """Return an iterator with tuples that describe the start and end of
    array of ``length`` where each slice has at most ``chunksize`` elements"""
    if length == 0:
        return
    starts = iter(range(0, length, chunksize))
    start = next(starts)
    for i in starts:
        yield (start, i)
        start = i
    yield (start, length)


def _block_slices(blocks, chunksize):
    """Return an iterator with tuples that describe the start and end of
    array of sorted ids in ``blocks`` where the chunk breaks happen on
    id change and every chunk is approximately ``chunksize`` elements in
    size."""
    start = 0
    while True:
        if len(blocks) - start <= chunksize:
            yield (start, len(blocks))
            break
        start_block = blocks[start+chunksize-1]
        for i, block in enumerate(blocks[start+chunksize:], start + chunksize):
            if block != start_block:
                yield (start, i)
                start = i
                break
        else:
            yield (start, i+1)
            break


def _summarise_chunk(args):
    global _groups
    groups = _groups
    global _values
    values = _values
    global _blocks
    blocks = _blocks
    all_groups, duplicates, idx = args
    start, stop = idx

    current_block = None
    current_block_id = None

    adjusted_ranks = defaultdict(float)
    # how many times a group is present in a block adjusted by individual
    # block sizes
    block_counts = defaultdict(int)
    # how many times the values are paired with each-other
    pair_counts = defaultdict(int)

    for val, group, block in zip(values[start:stop],
                                 groups[start:stop],
                                 blocks[start:stop]):
        # new block detected, summarise the current block, start a new one
        if block != current_block_id:
            # summarise the tuple only if there is more than one measurement
            # in the tuple (block)
            if current_block is not None and len(current_block) > 1:
                _summarise_tuple(current_block, all_groups, adjusted_ranks,
                                 block_counts, pair_counts)

            # prepare for new block analysis
            if current_block_id is not None and block < current_block_id:
                raise ValueError("blocks are not sorted")
            current_block_id = block
            current_block = dict()

        # add new value to the current block if it's consistent with
        # other values and settings
        if group not in current_block:
            current_block[group] = val
        else:
            if duplicates == 'last':
                current_block[group] = val
            elif duplicates is None:
                raise ValueError("Duplicate group ({0}) in block ({1})".format(
                                 group, block))

    if current_block is None:
        raise ValueError("Empty data set")
    if len(current_block) > 1:
        _summarise_tuple(current_block, all_groups, adjusted_ranks,
                         block_counts, pair_counts)

    return stop - start, adjusted_ranks, block_counts, pair_counts


def skillings_mack_test(values, groups, blocks, duplicates=None, status=None):
    """Perform the Skillings-Mack rank sum test.

    Skillings-Mack test is a Friedman-like test for unbalanced incomplete
    block design data. The null hypothesis is that no group stochastically
    dominates any other group, alternative hypothesis is that in at least
    one pair of groups one stochastically dominates the other.

    The test requires measurements to be independent within blocks and
    that the missing values are either partially balanced or random.

    ``values``, ``groups``, and ``blocks`` must have equal length.

    Reference: Skillings, J. H., Mack, G.A. (1981) On the use of a
    Friedman-type statistic in balanced and unbalanced block designs,
    Technometrics 23, 171-177

    Note: while the arguments have to be list-like, the function accepts
    memory mapped files and allows processing data sets larger than
    available system memory.

    Function is not thread-safe.

    :param list-like values: a list containing values that can be ranked
      (int, float, etc.)
    :param list-like groups: a list describing which group the corresponding
      value belongs to, the elements must be hashable
    :param list-like blocks: a list describing which test block the
      corresponding value belongs to, the elements must be sorted in the
      smallest-first order (e.g.: 1, 1, 1, 2, 2, 2, 2, 3,...)
    :param str duplicates: if set to None (default), will refuse to process
      duplicate data entries, if set to ``first`` it will use the first
      value of specific group in the given block, if set to ``last`` it
      will use the last value in a block
    :param list status: optional three-element list to communicate progress
      to the ``progress_report()`` method
    :return: named tuple with values of (``p_value``, ``T``, ``df``)
    """
    assert duplicates is None or duplicates in ('first', 'last')

    if not (len(groups) == len(values) == len(blocks)):
        raise ValueError("values, groups, and blocks must be the same length")

    if status is not None:
        status[1] = len(groups) + 1

    global _groups
    _groups = groups
    global _values
    _values = values
    global _blocks
    _blocks = blocks

    all_groups = set()
    with Pool() as p:
        # slice the data so that every worker has at least good few
        # dozen megabytes of data to work with
        chunks = p.imap_unordered(_set_unique, _slices(len(groups),
                                                       1024*1024*64))

        for i in chunks:
            all_groups.update(i)

        if status is not None:
            status[0] = 1

        adjusted_ranks = defaultdict(float)
        # how many times a group is present in a block adjusted by individual
        # block sizes
        block_counts = defaultdict(int)
        # how many times the values are paired with each-other
        pair_counts = defaultdict(int)

        # smaller chunk size gives better updates on progress and
        # less of a rounding error with summing
        chunk_size = min(1024*1024,
                         max(10, len(blocks) // (os.cpu_count() * 100)))

        chunks = p.imap_unordered(_summarise_chunk,
                                  ((all_groups, duplicates, i) for i in
                                   _block_slices(blocks, chunk_size)))

        for progress, chunk_ranks, chunk_block_counts, chunk_pair_counts \
                in chunks:
            if status is not None:
                status[0] += progress
            for k, v in chunk_ranks.items():
                adjusted_ranks[k] += v
            for k, v in chunk_block_counts.items():
                block_counts[k] += v
            for k, v in chunk_pair_counts.items():
                pair_counts[k] += v

    # check if all the groups present in data were compared with at
    # least one other group
    used_groups = set()
    for a, b in pair_counts.keys():
        used_groups.add(a)
        used_groups.add(b)
    for i in all_groups:
        if i not in used_groups:
            raise ValueError("Groups with no comparisons found")

    # numpy arrays are easier to handle with numerical indexes, so create
    # a mapping between names and integers
    mapping = dict((val, i) for i, val in enumerate(sorted(all_groups)))

    #
    # calculate the covariance matrix to get the test statistic
    #

    # while the elements are ints, we will be multiplying it by floats
    # (adjusted_ranks) later, so convert already to floats
    # missing combinations should be equal 0
    cov = np.full((len(all_groups), len(all_groups)),
                  0,
                  dtype=np.dtype('float64'))

    for k, v in pair_counts.items():
        x, y = k
        x = mapping[x]
        y = mapping[y]
        cov[x, y] = -v
        cov[y, x] = -v

    for k, v in block_counts.items():
        k = mapping[k]
        cov[k, k] = v

    rank_ar = np.full((len(all_groups), 1),
                      float('NaN'),
                      dtype=np.dtype('float64'))
    for k, v in adjusted_ranks.items():
        k = mapping[k]
        rank_ar[k] = v

    # calculate the test statistic (matrix multiply)
    T = np.matmul(np.matmul(np.transpose(rank_ar), np.linalg.pinv(cov)),
                  rank_ar)
    # result is a 1 by 1 matrix so extract that singular value
    T = T[0, 0]

    p_val = distributions.chi2.sf(T, len(all_groups) - 1)

    return skillings_mack_result(p_val, T, len(all_groups) - 1)
