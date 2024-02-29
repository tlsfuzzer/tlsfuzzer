# Author: Alicja Kario
# Released under Gnu GPL v2.0, see LICENCE for details
"""Class for calculating exact sums of different magnitude integers."""


class Summer(object):
    """
    Object for exactly summing a list of floating point numbers.

    after: https://code.activestate.com/recipes/393090/

    an object variant of the ``math.fsum`` method
    """

    def __init__(self, value=None):
        """Initialise the object

        ``value`` can be another Summer object (this will create a copy),
        a ``float``, or an iterable of ``float`` objects.
        """
        self.__partials = []
        if value is not None:
            if isinstance(value, Summer):
                self.__partials = value.__partials[:]
            elif isinstance(value, float):
                self += value
            else:
                self.update(value)

    def __add__(self, other):
        if not isinstance(other, (float, Summer)):
            return NotImplemented
        copy = Summer()
        copy.__partials.extend(self.__partials)
        copy += other
        return copy

    def dump(self):
        print(self.__partials)

    def __iadd__(self, other):
        if not isinstance(other, (float, Summer)):
            return NotImplemented
        if isinstance(other, Summer):
            return self.update(other.__partials)
        x = other
        i = 0
        for y in self.__partials:
            if abs(x) < abs(y):
                x, y = y, x
            hi = x + y
            lo = y - (hi - x)
            if lo:
                self.__partials[i] = lo
                i += 1
            x = hi
        self.__partials[i:] = [x]
        return self

    def __radd__(self, other):
        return self + other

    def __float__(self):
        return float(sum(self.__partials, 0.0))

    def __eq__(self, other):
        if not isinstance(other, (float, Summer)):
            return NotImplemented
        if isinstance(other, float):
            return float(self) == other
        return len(self.__partials) == len(other.__partials) and \
                all(i == j for i, j in zip(self.__partials, other.__partials))

    def update(self, values):
        for i in values:
            self += i
        return self

