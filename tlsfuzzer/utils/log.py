# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Utilities for logging the conversations for later timing analysis."""

import json
from random import shuffle


class Log:
    """Tools to interact with log files for later timing analysis."""

    def __init__(self, filename):
        """
        Initialises Log class with filename.

        :param str filename: log filename
        """
        self.filename = filename
        self.log = {
            "classes": [],
            "runs": []
        }

    def set_classes_list(self, class_list):
        """
        Inserts list of classes name into internal list.
        :param list class_list: List of test classes to be used to identify a
            connection later during the analysis
        """
        self.log["classes"] = class_list

    def add_run(self, run):
        """
        Appends a new run order
        :param list run: List of (shuffled) indexes to the "classes" list
        """
        self.log["runs"].append(run)

    def shuffle_new_run(self):
        """
        Generates a new test order as an index to the "classes" list
        """
        original_order = list(range(0, len(self.log["classes"])))
        shuffle(original_order)
        self.add_run(original_order)

    def write_log(self):
        """Write collected log information into a file."""
        with open(self.filename, 'w') as logfile:
            json.dump(self.log, logfile)

    def read_log(self):
        """Read classes from log file into internal list."""
        with open(self.filename, 'r') as logfile:
            self.log = json.load(logfile)

    def get_classes(self):
        """
        Get class names from current log
        :return: list  Class names list
        """
        return self.log["classes"]

    def iterate_log(self):
        """Provide a generator to iterate over runs."""
        for run in self.log["runs"]:
            for index in run:
                yield index
