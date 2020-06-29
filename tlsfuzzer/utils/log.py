# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Utilities for logging the conversations for later timing analysis."""

import csv
from random import shuffle


class Log:
    """Tools to interact with log files for later timing analysis."""

    def __init__(self, filename):
        """
        Initialises Log class with filename.

        :param str filename: log filename
        """
        self.filename = filename
        self.classes = []
        self.writer = None
        self.logfile = None
        self.reader = None

    def __del__(self):
        if self.logfile:
            self.logfile.close()

    def add_run(self, run):
        """
        Appends a new run order.

        :param list run: List of (shuffled) indexes to the "classes" list
        """
        self.writer.writerow(run)

    def shuffle_new_run(self):
        """
        Generates a new test order as an index to the "classes" list
        """
        original_order = list(range(0, len(self.classes)))
        shuffle(original_order)
        self.add_run(original_order)

    def start_log(self, class_list):
        """
        Start a new log and write classes on the first line.

        :param list class_list: List of test classes to be used to identify a
            connection later during the analysis
        """
        if self.logfile:
            self.logfile.close()
        self.logfile = open(self.filename, 'w')
        self.classes = class_list
        self.writer = csv.writer(self.logfile)
        self.writer.writerow(self.classes)

    def write(self):
        """Close the log file, forcing system to write it."""
        self.logfile.close()

    def read_log(self):
        """Read classes from log file into internal list."""
        if self.logfile:
            self.logfile.close()
        self.logfile = open(self.filename, 'r')
        self.reader = csv.reader(self.logfile)
        self.classes = next(self.reader)

    def get_classes(self):
        """
        Get class names from current log
        :return: list  Class names list
        """
        if not self.reader:
            self.read_log()
        return self.classes

    def iterate_log(self):
        """Provide a generator to iterate over runs."""
        if not self.reader:
            self.read_log()

        for run in self.reader:
            for index in run:
                yield int(index)
