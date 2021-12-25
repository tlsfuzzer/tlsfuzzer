# Author: Hubert Kario, (c) 2021
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Filtering out the dependence between query timings and responses."""

from __future__ import print_function

import getopt
import sys
import csv
import time
import math
from os.path import join

import pandas as pd
import numpy as np
import hdbscan

def help_msg():
    """Print help message."""
    print("Usage: filter -i input -n column -o output")
    print(" -o output      Output file name")
    print(" -i input       Input file name, must have at least two columns")
    print(" -n column      Name of the column that contains response times")
    print(" --help         Display this message")
    print("")

def main():
    """Process arguments and start extraction."""
    output = None
    input_file = None
    col_name = None

    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "o:i:n:", ["help"])
    for opt, arg in opts:
        if opt == '-o':
            output = arg
        elif opt == '-i':
            input_file = arg
        elif opt == '-n':
            col_name = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)

    if not all([input_file, output, col_name]):
        raise ValueError(
            "All options are mandatory")

    fil = Filter(input_file, output, col_name)
    fil.read_pkt_csv()
    fil.k_means_cluster()
    fil.lin_regression()
    fil.write_csv()


class Filter(object):
    """Extract timing information from packet capture."""

    def __init__(self, input_file, output_file, col_name):
        """
        Initialises instance.

        :param str input_file: File name to read with initial data
        :param str output_file: File name where to output results
        :param str col_name: Name of column to disassociate from the others
        """
        self.input_file = input_file
        self.output_file = output_file
        self.col_name = col_name

    def k_means_cluster(self):
        print("Starting HDBSCAN...")
        clusterer = hdbscan.HDBSCAN(min_cluster_size=10)
        labels = clusterer.fit_predict(self.data)
        self.labels = labels
        bins = set(labels)
        bin_counts = [sum(i == x for i in labels) for x in bins]
        print("Clustering done, groups: {2}, smallest group size: {0}, largest: {1}."
              .format(min(bin_counts), max(bin_counts), len(bin_counts)))

    def read_pkt_csv(self):
        with open(self.input_file, "r") as csvfile:
            print("Reading {0}".format(self.input_file))
            data = pd.read_csv(self.input_file, dtype=np.float64)
            self.data = data
        print("Data read.")

    def lin_regression(self):
        """Run linear regression on individual data clusters."""
        print("Calculating linear regression on individual groups...")
        if self.col_name not in self.data.columns:
            raise ValueError("Column name \"{0}\" not in {1}".format(
                self.col_name, self.data.columns))

        coef_names = [i for i in self.data.columns if i != self.col_name]
        dep = self.data[[self.col_name]]

        all_labels = set(self.labels)
        res = pd.DataFrame(columns=[self.col_name])

        for group in all_labels:
            l_coef = self.data.loc[self.labels == group, coef_names]
            # add the constant (intercept) to the linear equation
            l_coef['__constant'] = np.ones(len(l_coef))
            l_dep = dep[self.labels == group]
            x_param = np.linalg.lstsq(l_coef, l_dep, rcond=None)[0]

            predicted = np.dot(l_coef, x_param)
            # calculate the residual but keep the offset from zero
            # so that differences between classes in in analysis.py make sense
            res_0 = predicted - l_dep + np.median(l_dep)

            res = pd.concat([res, res_0])

        res.sort_index(inplace=True)

        self.timings = res
        print("Linear regression done.")

    def write_csv(self):
        """
        Write timing information into a csv file. Each row is a single
        measurement.

        :param str filename: Target filename
        """
        with open(self.output_file, 'w') as csvfile:
            print("Writing to {0}".format(self.output_file))
            self.timings.to_csv(csvfile, index=False)


if __name__ == '__main__':
    main()
