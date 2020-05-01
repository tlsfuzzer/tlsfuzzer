# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Utilities for logging the conversations for later timing analysis."""

from itertools import cycle


class Log:
    """Class that provides tools to interact with log files for later timing analysis."""

    def __init__(self, filename):
        """
        Initialises Log class with filename.

        :param str filename: log filename
        """
        self.filename = filename
        self.log = []

    def add_class_name(self, class_name):
        """
        Inserts class name into internal list.
        :param str class_name: Class name to identify connection with
        """
        self.log.append(class_name)

    def write_log(self):
        """Write collected log information into a file."""
        with open(self.filename, 'w') as logfile:
            for line in self.log:
                logfile.write(line)
                logfile.write('\n')

    def read_log(self):
        """Read classes from log file into internal list."""
        log = []
        with open(self.filename, 'r') as logfile:
            for line in logfile:
                log.append(line.rstrip("\n"))
        self.log = log

    def iterate_log(self):
        """Provide a generator to iterate over classes infinitely."""
        for item in cycle(self.log):
            yield item
