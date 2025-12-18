# Author: Alicja Kario
# Released under Gnu GPL v2.0, see LICENCE for details
"""Class for keeping some running statistics of a sample."""

import math
from .summer import Summer


class RunningSampleStats(object):
    """
    Object for keeping exact values of certain sample statistics as the
    sample is getting continuously extended.

    Provides sample size, mean, average and standard deviation.
    """
    def __init__(self, value=None):
        self.__sum = Summer()
        self.__sum_of_squares = Summer()
        self.__count = 0

    def update(self, values):
        for i in values:
            self.__sum += i
            self.__sum_of_squares += i*i
            self.__count += 1

    def mean(self):
        """Return the arithmetic mean of the sample."""
        return float(self.__sum) / self.__count

    def stdev(self):
        """Return the standard deviation of the sample."""
        return math.sqrt(
            (self.__count * float(self.__sum_of_squares) -
             float(self.__sum) ** 2) / (self.__count * (self.__count - 1)))

    def sum(self):
        """Return the sum of all the elements in the sample."""
        return float(self.__sum)

    def __len__(self):
        """Return the number of elements in the sample."""
        return self.__count
