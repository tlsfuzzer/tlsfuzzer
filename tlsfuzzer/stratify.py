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
from scipy.cluster.vq import kmeans2
from tlsfuzzer.utils.log import Log


def help_msg():
    """Print help message."""
    print("Usage: filter -i input -n column -l log -o output")
    print(" -o output      Output file name")
    print(" -i input       Input file name, must have at least two columns")
    print(" -n column      Name of the column that contains response times")
    print(" -l log         Input file name, contains the probe order of input")
    print(" --help         Display this message")
    print("")


def main():
    """Process arguments and start extraction."""
    output = None
    log_file = None
    input_file = None
    col_name = None

    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "o:i:l:n:", ["help"])
    for opt, arg in opts:
        if opt == '-o':
            output = arg
        elif opt == '-i':
            input_file = arg
        elif opt == '-n':
            col_name = arg
        elif opt == '-l':
            log_file = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)

    if not all([input_file, output, log_file, col_name]):
        raise ValueError(
            "All options are mandatory")

    fil = Stratify(input_file, log_file, output, col_name)
    fil.read_pkt_csv()
    fil.k_means_cluster()
    fil.stratify()
    fil.write_csv()


class Stratify(object):
    """
    Try to clean up timing information by stratification.

    As the execution state of the machine has effect on both time to prepare
    the query and on query exection. As well as that the contents of the
    query can have effect on time to prepare the query. The other collected
    times effectively affect the server response time.

    Stratify the collected data using k-means and compare the tuples only
    within clusters, i.e. rebuild tuples using k-means instead of only the
    log file.
    """

    def __init__(self, input_file, log_file, output_file, col_name):
        """
        Initialises instance.

        :param str input_file: File name to read with initial data
        :param str log_file: File name to read the probe assignments from
        :param str output_file: File name where to output results
        :param str col_name: Name of column to disassociate from the others
        """
        self.input_file = input_file
        log = Log(log_file)
        log.read_log()
        self.classes = list(log.iterate_log())
        self.class_names = log.get_classes()
        self.output_file = output_file
        self.col_name = col_name

    def k_means_cluster(self):
        # just an arbitrary number that won't cause massive memory usage
        # for large samples
        k = 1024
        # but also don't make the k similar in size to sample size, while
        # still performing clustering
        k = min(k, max(len(self.data)//50 + 1, 2))
        data = self.data.copy()
        # lst_srv_to_syn is a bad predictor
        del data['lst_srv_to_syn']
        # don't use the result colum for clustering
        del data[self.col_name]
        print("Starting k-means clustering (k={0})...".format(k))
        # first element returned is the list of centroids of the clusters
        _, labels = kmeans2(data, k, minit='++')
        self.labels = labels
        bin_counts = np.bincount(labels)
        print("Clustering done, smallest group size: {0}, largest: {1}."
              .format(min(bin_counts), max(bin_counts)))

    def read_pkt_csv(self):
        with open(self.input_file, "r") as csvfile:
            print("Reading {0}".format(self.input_file))
            data = pd.read_csv(self.input_file, dtype=np.float64)
            self.data = data
        print("Data read.")

    def stratify(self):
        data = self.data.copy()
        all_classes = set(self.classes)
        data['__class'] = self.classes
        all_labels = set(self.labels)
        res = pd.DataFrame(columns=self.class_names)

        for label in all_labels:
            sub_sample = data.loc[self.labels == label, ['__class', self.col_name]]
            new_tuples = list(zip(
                *[sub_sample.loc[sub_sample['__class'] == i, self.col_name]
                for i in sorted(all_classes)]
            ))
            if not new_tuples:
                continue
            new_tuples = pd.DataFrame(np.array(new_tuples), columns=self.class_names)
            res = pd.concat([res, new_tuples])

        self.timings = res

    def write_csv(self):
        """
        Write timing information into a csv file. Each row is a results tuple.

        :param str filename: Target filename
        """
        print("original data size: {0}".format(len(self.data.index)))
        print("filtered data size: {0}".format(self.timings.shape[0] * self.timings.shape[1]))
        with open(self.output_file, 'w') as csvfile:
            print("Writing to {0}".format(self.output_file))
            self.timings.to_csv(csvfile, index=False)


if __name__ == '__main__':
    main()
