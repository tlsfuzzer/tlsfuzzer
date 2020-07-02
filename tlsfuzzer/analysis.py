# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details

"""Analysis of timing information."""

from __future__ import print_function

import csv
import getopt
import sys
from os.path import join
from collections import namedtuple
from itertools import combinations, product

import numpy as np
from scipy import stats
import pandas as pd
import matplotlib.pyplot as plt

TestPair = namedtuple('TestPair', 'index1  index2')


def help_msg():
    """Print help message"""
    print("Usage: analysis [-o output]")
    print(" -o output      Directory where to place results (required)")
    print("                and where timing.csv is located")
    print(" --help         Display this message")


def main():
    """Process arguments and start analysis."""
    output = None
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "o:", ["help"])

    for opt, arg in opts:
        if opt == '-o':
            output = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)

    if output:
        analysis = Analysis(output)
        analysis.generate_report()
    else:
        raise ValueError("Missing -o option!")


class Analysis:
    """Analyse extracted timing information from csv file."""

    def __init__(self, output):
        self.output = output
        self.data = self.load_data()
        self.class_names = list(self.data)

    def load_data(self):
        """Loads data into pandas Dataframe for generating plots and stats."""
        data = pd.read_csv(join(self.output, "timing.csv"), header=None)

        # transpose and set header
        data = data.transpose()
        data = data.rename(columns=data.iloc[0]).drop(data.index[0])
        return data

    def _box_test(self, interval1, interval2, quantile_start, quantile_end):
        """
        Internal configurable function to perform the box test.

        :param int interval1: index to self.data representing first sample
        :param int interval2: index to self.data representing second sample
        :param float quantile_start: starting quantile of the box
        :param float quantile_end: closing quantile of the box
        :return: None on no difference, int index of smaller sample if there
            is a difference
        """
        box1_start = np.quantile(self.data.iloc[:, interval1], quantile_start)
        box1_end = np.quantile(self.data.iloc[:, interval1], quantile_end)

        box2_start = np.quantile(self.data.iloc[:, interval2], quantile_start)
        box2_end = np.quantile(self.data.iloc[:, interval2], quantile_end)

        if box1_start == box2_start or box1_end == box2_end:
            # can return early because the intervals overlap
            return None

        intervals = {interval1: (box1_start, box1_end),
                     interval2: (box2_start, box2_end)}
        is_smaller = min(box1_start, box2_start) == box1_start
        smaller = interval1 if is_smaller else interval2
        bigger = interval2 if smaller == interval1 else interval1

        if (intervals[smaller][0] < intervals[bigger][0] and
                intervals[smaller][1] < intervals[bigger][0]):
            return smaller, bigger
        return None

    def box_test(self):
        """Cross-test all classes with the box test"""
        results = {}
        comb = combinations(list(range(len(self.class_names))), 2)
        for index1, index2 in comb:
            result = self._box_test(index1, index2, 0.03, 0.04)
            results[TestPair(index1, index2)] = result
        return results

    def wilcoxon_test(self):
        """Cross-test all classes with the Wilcoxon signed-rank test"""
        results = {}
        comb = combinations(list(range(len(self.class_names))), 2)
        for index1, index2 in comb:
            data1 = self.data.iloc[:, index1]
            data2 = self.data.iloc[:, index2]
            _, pval = stats.wilcoxon(data1, data2)
            results[TestPair(index1, index2)] = pval
        return results

    def box_plot(self):
        """Generate box plot for the test classes."""
        axes = self.data.plot(kind="box", showfliers=False)
        axes.set_xticks(range(len(self.data)))
        axes.set_xticklabels(list(range(len(self.data))))

        plt.title("Box plot")
        plt.ylabel("Time [s]")
        plt.xlabel("Class index")
        plt.savefig(join(self.output, "box_plot.png"), bbox_inches="tight")
        plt.close()

    def qq_plot(self):
        """Generate Q-Q plot grid for the test classes."""
        indexes = list(range(len(self.class_names)))
        prod = product(indexes, repeat=2)
        data_length = len(self.data.iloc[:, 1])
        quantiles = np.linspace(start=0, stop=1, num=int(data_length))

        fig, axes = plt.subplots(len(indexes),
                                 len(indexes),
                                 figsize=(len(indexes) * 3, len(indexes) * 3))

        for index1, index2 in prod:
            data1 = self.data.iloc[:, index1]
            data2 = self.data.iloc[:, index2]
            quantile1 = np.quantile(data1, quantiles, interpolation="midpoint")
            quantile2 = np.quantile(data2, quantiles, interpolation="midpoint")
            plot = axes[index1, index2]
            if index1 == 0:
                plot.set_title(index2)
            if index2 == 0:
                plot.set_ylabel(index1,
                                fontsize=plt.rcParams['axes.titlesize'])
            plot.scatter(quantile1, quantile2, marker=".")
            plot.set_xticks([])
            plot.set_yticks([])
            plot.set_xlim([quantile1[0], quantile1[-1]])
            plot.set_ylim([quantile2[0], quantile2[-1]])

        fig.suptitle("Q-Q plot grid")
        plt.subplots_adjust(top=0.92,
                            bottom=0.05,
                            left=0.1,
                            right=0.925)
        plt.savefig(join(self.output, "qq_plot.png"), bbox_inches="tight")
        plt.close()

    def scatter_plot(self):
        """Generate scatter plot showing how the measurement went."""
        plt.figure(figsize=(8, 6))
        plt.plot(self.data, ".", fillstyle='none', alpha=0.6)

        plt.title("Scatter plot")
        plt.ylabel("Time [s]")
        plt.xlabel("Sample index")
        plt.yscale("log")
        self.make_legend()
        plt.savefig(join(self.output, "scatter_plot.png"), bbox_inches="tight")
        plt.close()

    def ecdf_plot(self):
        """Generate ECDF plot comparing distributions of the test classes."""
        plt.figure()
        for classname in self.data:
            data = self.data.loc[:, classname]
            levels = np.linspace(1. / len(data), 1, len(data))
            plt.step(sorted(data), levels, where='post')
        self.make_legend()
        plt.title("Empirical Cumulative Distribution Function")
        plt.xlabel("Time [s]")
        plt.ylabel("Cumulative probability")
        plt.savefig(join(self.output, "ecdf_plot.png"), bbox_inches="tight")
        plt.close()

    def make_legend(self):
        """Generate common legend for plots that need it."""
        header = list(range(len(list(self.data))))
        plt.legend(header,
                   ncol=6,
                   loc='upper center',
                   bbox_to_anchor=(0.5, -0.15)
                   )

    def generate_report(self):
        """
        Compiles a report consisting of statistical tests and plots.

        :return: int 0 if no difference was detected, 1 otherwise
        """
        self.box_plot()
        self.scatter_plot()
        self.qq_plot()
        self.ecdf_plot()

        difference = 0

        # create a report with statistical tests
        box_results = self.box_test()
        wilcox_results = self.wilcoxon_test()

        report_filename = join(self.output, "report.csv")
        p_vals = []
        with open(report_filename, 'w') as file:
            writer = csv.writer(file)
            writer.writerow(["Class 1", "Class 2", "Box test",
                             "Wilcoxon signed-rank test"])
            for pair, result in box_results.items():
                index1 = pair.index1
                index2 = pair.index2
                box_write = "="
                if result:
                    smaller, bigger = result
                    print("Box test {} vs {}: {} < {}".format(index1,
                                                              index2,
                                                              smaller,
                                                              bigger))
                    box_write = "<" if smaller == index1 else ">"
                else:
                    print("Box test {} vs {}: No difference".format(index1,
                                                                    index2))
                print("Wilcoxon signed-rank test {} vs {}: {}"
                      .format(index1, index2, wilcox_results[pair]))
                # if both tests found a difference
                # consider it a possible side-channel
                if result and wilcox_results[pair] < 0.05:
                    difference = 1

                row = [self.class_names[index1],
                       self.class_names[index2],
                       box_write,
                       wilcox_results[pair]
                       ]
                writer.writerow(row)

                p_vals.append(wilcox_results[pair])

        legend_filename = join(self.output, "legend.csv")
        with open(legend_filename, "w") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['ID', 'Name'])
            for num, name in enumerate(self.class_names):
                writer.writerow([num, name])

        _, p = stats.kstest(p_vals, 'uniform')
        print("KS-test for uniformity of p-values from Wilcoxon signed-rank "
              "test")
        print("p-value: {}".format(p))
        if p < 0.05:
            difference = 1

        print("For detailed report see {}".format(report_filename))
        return difference


if __name__ == '__main__':
    main()
