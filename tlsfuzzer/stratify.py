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
from itertools import chain

import pandas as pd
import numpy as np
import hdbscan
from scipy.cluster.vq import kmeans2
from tlsfuzzer.utils.log import Log
from sklearn.cluster import KMeans


def help_msg():
    """Print help message."""
    print("Usage: filter -i input -n column -l log -o output")
    print(" -o output      Output file name")
    print(" -i input       Input file name, must have at least two columns")
    print(" -n column      Name of the column that contains response times")
    print(" -l log         Input file name, contains the probe order of input")
    print(" --raw-times    Output raw_times_detail.csv and log.csv instead timing.csv")
    print(" --help         Display this message")
    print("")


def main():
    """Process arguments and start extraction."""
    output = None
    log_file = None
    input_file = None
    col_name = None
    raw_times = False

    argv = sys.argv[1:]

    if not argv:
        help_msg()
        sys.exit(1)

    opts, args = getopt.getopt(argv, "o:i:l:n:", ["help", "raw-times"])
    for opt, arg in opts:
        if opt == '-o':
            output = arg
        elif opt == '-i':
            input_file = arg
        elif opt == '-n':
            col_name = arg
        elif opt == '-l':
            log_file = arg
        elif opt == "--raw-times":
            raw_times = True
        elif opt == "--help":
            help_msg()
            sys.exit(0)

    if not all([input_file, output, log_file, col_name]):
        raise ValueError(
            "All options are mandatory")

    fil = Stratify(input_file, log_file, output, col_name)
    fil.read_pkt_csv()
    fil.k_means_cluster()
    if raw_times:
        fil.raw_stratify()
    else:
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
        data = self.data.copy()

        #import matplotlib.pyplot as plt
        #data['__classes'] = self.classes
        #pd.plotting.parallel_coordinates(data[1:10000], '__classes', cols=['ack_to_lst_clnt', 'syn_to_syn_ack', 'lst_clnt_to_lst_srv', 'syn_ack_to_ack', 'lst_srv_to_syn'], color=('#556270', '#4ECDC4', '#C7F464'))
        #plt.show()

        # lst_srv_to_syn is a bad predictor
        if 'lst_srv_to_syn' in data:
            del data['lst_srv_to_syn']
        #del data['lst_msg_to_syn']

        # don't use the result colum for clustering
        del data[self.col_name]
        # or the alternative result column
        del data['prv_ack_to_srv_0']

        # also don't use uncorrelated columns
        #del data['srv_0_ack']
        #del data['lst_srv_to_srv_fin']
        print("Starting HDBSCAN clustering...")
        # stats from test-down-for.py_v1_1637085594
        # clusterer = hdbscan.HDBSCAN(min_samples=1, min_cluster_size=5) outliers: 87168, clusters: 23526, max cluster size: 659, sign test: 5.21e-08
        # clusterer = hdbscan.HDBSCAN(cluster_selection_method='leaf') outliers: 221350, clusters: 8742, max cluster size: 66, sign test: 1.67e-21
        # clusterer = hdbscan.HDBSCAN(cluster_selection_method='leaf', min_samples=1, min_cluster_size=5) outliers: 94957, clusters: 25190, max cluster size: 41, sign test: 1e-11
        clusterer = hdbscan.HDBSCAN(cluster_selection_method='leaf', leaf_size=5, min_samples=1, min_cluster_size=3, metric='manhattan')
        # clusterer = hdbscan.HDBSCAN(cluster_selection_method='leaf', min_samples=1, min_cluster_size=10) outliers: 131027, clusters: 10040, max cluster size: 80, sign test: 2.14e-26
        # clusterer = hdbscan.HDBSCAN(cluster_selection_method='leaf', cluster_selection_epsilon=3e-9, min_samples=1, min_cluster_size=5) outliers: 94957, clusters: 25190, max cluster size: 41, sign test: 1e-11
        # clusterer = hdbscan.HDBSCAN(cluster_selection_method='leaf', cluster_selection_epsilon=2e-9, min_samples=1, min_cluster_size=2) outliers: 53352, clusters: 90552, max cluster size: 13, sign test: 0.000266
        # clusterer = hdbscan.HDBSCAN(cluster_selection_method='leaf', leaf_size=10, cluster_selection_epsilon=3e-9, min_samples=1, min_cluster_size=5) outliers: 94503, clusters: 25200, max cluster size: 41, sign test: 3.13e-10
        labels = clusterer.fit_predict(data)
        from collections import Counter
        bins = Counter(labels)
        outliers = bins.pop(-1, 0)
        bin_counts = bins.values()
        print("HDBSCAN clustering done, groups {2}, outliers: {3}, smallest group size: {0}, largest: {1}."
              .format(min(bin_counts), max(bin_counts), len(bin_counts), outliers))

        #k = 1024
        #print("Re-clustering outliers, k={0}".format(k))
        #_, k_labels = kmeans2(data.loc[labels == -1], k, minit="++")

        #labels[labels == -1] = k_labels + max(labels) + 1

        #print("outliers re-clustered")

        #bins = Counter(labels)
        #outliers = bins.pop(-1, 0)
        #bin_counts = bins.values()
        #print("Clustering done, groups {2}, outliers: {3}, smallest group size: {0}, largest: {1}."
        #      .format(min(bin_counts), max(bin_counts), len(bin_counts), outliers))


        import matplotlib.pyplot as plt
        for i in [-1] + sorted(bins.keys(), key=lambda x: bins[x], reverse=True)[:15]:
            print("label: {0}, size: {1}".format(i, bins.get(i, outliers)))
            #plt.scatter(self.data.loc[labels == i, ['ack_to_lst_clnt']], self.data.loc[labels == i, ['lst_clnt_to_lst_srv']], marker='.', alpha=0.3)
            #plt.show()

        self.labels = labels

    def read_pkt_csv(self):
        with open(self.input_file, "r") as csvfile:
            print("Reading {0}".format(self.input_file))
            data = pd.read_csv(self.input_file, dtype=np.float64)
            self.data = data
        print("Data read.")

    def raw_stratify(self):
        print("Starting stratification")
        data = self.data.copy()
        all_classes = set(self.classes)
        data['__class'] = self.classes
        all_labels = set(self.labels)
        res = pd.DataFrame(columns=self.data.columns)

        data = data.sample(frac=1).reset_index(drop=True)

        for label in all_labels:
            if label == -1:
                continue
            sub_sample = data.loc[self.labels == label]
            new_tuples = list(zip(
                *[sub_sample.loc[sub_sample['__class'] == i, self.data.columns].itertuples(index=False)
                for i in sorted(all_classes)]
            ))
            if not new_tuples:
                continue
            new_tuples = list(chain.from_iterable(new_tuples))
            new_tuples = pd.DataFrame(
                np.array(new_tuples),
                columns=self.data.columns
            )
            res = pd.concat((res, new_tuples))

        print("Stratification done, saving...")

        log_res = np.full(
            (len(res.index)//len(self.class_names), len(self.class_names)),
            range(len(self.class_names)),
            dtype=np.uint32
        )
        log_res = pd.DataFrame(log_res, columns=self.class_names)

        print("original data size: {0}".format(len(self.data.index)))
        print("filtered data size: {0}".format(len(res)))

        with open(self.output_file + "/raw_times_detail.csv", "w") as csvfile:
            res.to_csv(csvfile, index=False)
        with open(self.output_file + "/log.csv", "w") as csvfile:
            log_res.to_csv(csvfile, index=False)
        print("Done.")

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
