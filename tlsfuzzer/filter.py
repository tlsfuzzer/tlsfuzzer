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
        print("clustering:")
        data = self.data[['ack_to_lst_clnt', 'lst_clnt_to_lst_srv']]
        #data = self.data.copy()
        #data['__index'] = self.data.index / 1e9
        #del data['lst_srv_to_syn']
        print(data)
        clusterer = hdbscan.HDBSCAN(cluster_selection_method='leaf', alpha=0.5, leaf_size=10, min_cluster_size=10, min_samples=1, cluster_selection_epsilon=3e-9, metric="manhattan")
        #clusterer = hdbscan.HDBSCAN(cluster_selection_method="leaf", leaf_size=40, min_cluster_size=10, min_samples=1)
        labels = clusterer.fit_predict(data)
        print("clustered")
        self.labels = labels
        bins = set(labels)
        from collections import Counter
        bins = Counter(labels)
        outliers = bins.pop(-1, 0)
        bin_counts = bins.values()
        print("Clustering done, groups: {2}, smallest group size: {0}, largest: {1}, outliers: {3}."
              .format(min(bin_counts), max(bin_counts), len(bin_counts), outliers))
        import matplotlib.pyplot as plt
        #plt.scatter(data['ack_to_lst_clnt'], data['lst_clnt_to_lst_srv'], c=labels, marker=".", alpha=0.5)
        #plt.show()
        for i in [-1] + sorted(bins.keys(), key=lambda x: bins[x], reverse=True)[:5]:
            print("label: {0}, size: {1}".format(i, bins.get(i, outliers)))
            #plt.scatter(data.loc[labels == i, ['ack_to_lst_clnt']], data.loc[labels == i, ['lst_clnt_to_lst_srv']], marker=".", alpha=0.5)
            #plt.show()

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
            l_coef = self.data.loc[self.labels == group, ['ack_to_lst_clnt', 'lst_srv_to_syn']]
            # add the constant (intercept) to the linear equation
            #l_coef = l_coef['ack_to_lst_clnt']
            l_coef['__constant'] = np.ones(len(l_coef))
            del l_coef['lst_srv_to_syn']
            l_dep = dep[self.labels == group]
            #if group == -1:
                # don't apply regression to outliers
            #    res = pd.concat([res, l_dep])
            #    continue
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
