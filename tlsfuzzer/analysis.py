#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details


"""Analysis of timing information."""

from __future__ import print_function

import csv
import getopt
import sys
import multiprocessing as mp
from os.path import join
from collections import namedtuple
from itertools import combinations, repeat, chain
import os

import numpy as np
from scipy import stats
import pandas as pd
import matplotlib as mpl
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas

TestPair = namedtuple('TestPair', 'index1  index2')
mpl.use('Agg')


_diffs = None


def help_msg():
    """Print help message"""
    print("""Usage: analysis [-o output]
 -o output      Directory where to place results (required)
                and where timing.csv is located
 --no-ecdf-plot Don't create the ecdf_plot.png file
 --no-scatter-plot Don't create the scatter_plot.png file
 --no-conf-interval-plot Don't create the conf_interval_plot.png file
 --help         Display this message""")


def main():
    """Process arguments and start analysis."""
    output = None
    ecdf_plot = True
    scatter_plot = True
    conf_int_plot = True
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "o:",
                               ["help", "no-ecdf-plot", "no-scatter-plot",
                                "no-conf-interval-plot"])

    for opt, arg in opts:
        if opt == '-o':
            output = arg
        elif opt == "--help":
            help_msg()
            sys.exit(0)
        elif opt == "--no-ecdf-plot":
            ecdf_plot = False
        elif opt == "--no-scatter-plot":
            scatter_plot = False
        elif opt == "--no-conf-interval-plot":
            conf_int_plot = False

    if output:
        analysis = Analysis(output, ecdf_plot, scatter_plot, conf_int_plot)
        ret = analysis.generate_report()
        return ret
    else:
        raise ValueError("Missing -o option!")


class Analysis(object):
    """Analyse extracted timing information from csv file."""

    def __init__(self, output, draw_ecdf_plot=True, draw_scatter_plot=True,
                 draw_conf_interval_plot=True):
        self.output = output
        self.data = self.load_data()
        self.class_names = list(self.data)
        self.draw_ecdf_plot = draw_ecdf_plot
        self.draw_scatter_plot = draw_scatter_plot
        self.draw_conf_interval_plot = draw_conf_interval_plot

    def _convert_to_binary(self):
        timing_bin_path = join(self.output, "timing.bin")
        timing_csv_path = join(self.output, "timing.csv")
        legend_csv_path = join(self.output, "legend.csv")
        timing_bin_shape_path = join(self.output, "timing.bin.shape")
        if os.path.isfile(timing_bin_path) and \
                os.path.isfile(legend_csv_path) and \
                os.path.isfile(timing_bin_shape_path) and \
                os.path.getmtime(timing_csv_path) < \
                os.path.getmtime(timing_bin_path):
            return

        for chunk in pd.read_csv(timing_csv_path, chunksize=1,
                                 dtype=np.float64):
            self.class_names = list(chunk)
            self._write_legend()
            break

        ncol = len(self.class_names)

        rows_written = 0

        # as we're dealing with 9 digits of precision (nanosecond range)
        # and the responses can be assumed to take less than a second,
        # we need to use the double precision IEEE floating point numbers

        # load 512000 rows at a time so that we don't use more than 2000MiB
        # (including pandas overhead) of memory at a time to process a file
        # with 256 columns
        csv_reader = pd.read_csv(timing_csv_path, chunksize=512000,
                                 dtype=np.float64)
        chunk = next(csv_reader)
        timing_bin = np.memmap(timing_bin_path, dtype=np.float64,
                               mode="w+",
                               shape=(len(chunk.index), ncol),
                               order="C")
        timing_bin[:, :] = chunk.iloc[:, :]
        rows_written += len(chunk.index)
        del timing_bin

        for chunk in csv_reader:
            timing_bin = np.memmap(timing_bin_path, dtype=np.float64,
                                   mode="r+",
                                   shape=(rows_written + len(chunk.index),
                                          ncol),
                                   order="C")
            timing_bin[rows_written:, :] = chunk.iloc[:, :]
            rows_written += len(chunk.index)

            del timing_bin

        with open(timing_bin_shape_path, "w") as f:
            writer = csv.writer(f)
            writer.writerow(["nrow", "ncol"])
            writer.writerow([rows_written, ncol])

    def load_data(self):
        """Loads data into pandas Dataframe for generating plots and stats."""
        self._convert_to_binary()
        timing_bin_path = join(self.output, "timing.bin")
        legend_csv_path = join(self.output, "legend.csv")
        timing_bin_shape_path = join(self.output, "timing.bin.shape")

        with open(timing_bin_shape_path, "r") as f:
            reader = csv.reader(f)
            if next(reader) != ["nrow", "ncol"]:
                raise ValueError("Malformed {0} file, delete it and try again"
                                 .format(timing_bin_shape_path))
            nrow, ncol = next(reader)
            nrow = int(nrow)
            ncol = int(ncol)

        legend = pd.read_csv(legend_csv_path)

        if len(legend.index) != ncol:
            raise ValueError("Inconsistent {0} and {1} files, delete and try "
                             "again".format(legend_csv_path,
                                            timing_bin_shape_path))
        columns = list(legend.iloc[:, 1])

        timing_bin = np.memmap(timing_bin_path, dtype=np.float64,
                               mode="r", shape=(nrow, ncol), order="C")

        data = pd.DataFrame(timing_bin, columns=columns, copy=False)
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
        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        ax = fig.add_subplot(1, 1, 1)

        # a simpler alternative would use self.data.boxplot() but that
        # copies the data to the mathplot object
        # which means it doesn't keep it in a neat array.array, blowing up
        # the memory usage significantly
        # so calculate the values externally and just provide the computed
        # quantiles to the boxplot drawing function
        percentiles = self.data.quantile([0.05, 0.25, 0.5, 0.75, 0.95])

        boxes = []
        for name in percentiles:
            vals = [i for i in percentiles.loc[:, name]]
            boxes += [{'label': name,
                       'whislo': vals[0],
                       'q1': vals[1],
                       'med': vals[2],
                       'q3': vals[3],
                       'whishi': vals[4],
                       'fliers': []}]

        ax.bxp(boxes, showfliers=False)
        ax.set_xticks(list(range(len(self.data.columns)+1)))
        ax.set_xticklabels([''] + list(range(len(self.data.columns))))

        ax.set_title("Box plot")
        ax.set_ylabel("Time [s]")
        ax.set_xlabel("Class index")
        canvas.print_figure(join(self.output, "box_plot.png"),
                            bbox_inches="tight")

    def scatter_plot(self):
        """Generate scatter plot showing how the measurement went."""
        if not self.draw_scatter_plot:
            return None
        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        ax = fig.add_subplot(1, 1, 1)
        ax.plot(self.data, ".", fillstyle='none', alpha=0.6)

        ax.set_title("Scatter plot")
        ax.set_ylabel("Time [s]")
        ax.set_xlabel("Sample index")
        ax.set_yscale("log")
        self.make_legend(ax)
        canvas.print_figure(join(self.output, "scatter_plot.png"),
                            bbox_inches="tight")

    def ecdf_plot(self):
        """Generate ECDF plot comparing distributions of the test classes."""
        if not self.draw_ecdf_plot:
            return None
        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        ax = fig.add_subplot(1, 1, 1)
        for classname in self.data:
            data = self.data.loc[:, classname]
            levels = np.linspace(1. / len(data), 1, len(data))
            ax.step(sorted(data), levels, where='post')
        self.make_legend(ax)
        ax.set_title("Empirical Cumulative Distribution Function")
        ax.set_xlabel("Time [s]")
        ax.set_ylabel("Cumulative probability")
        canvas.print_figure(join(self.output, "ecdf_plot.png"),
                            bbox_inches="tight")

    def make_legend(self, fig):
        """Generate common legend for plots that need it."""
        header = list(range(len(list(self.data))))
        fig.legend(header,
                   ncol=6,
                   loc='upper center',
                   bbox_to_anchor=(0.5, -0.15)
                   )

    @staticmethod
    def _mean_of_random_sample(reps=100):
        """Calculate a mean with a single instance of bootstrapping."""
        ret = []
        global _diffs
        diffs = _diffs

        for _ in range(reps):
            boot = np.random.choice(diffs, replace=True, size=len(diffs))
            # use trimmed mean as the pairing of samples in not perfect:
            # the noise source could get activated in the middle of testing
            # of the test set, causing some results to be unusable
            # discard 50% of samples total (cut 25% from the median) to exclude
            # non central modes
            ret.append(stats.trim_mean(boot, 0.25))
        return ret

    def _bootstrap_differences(self, pair, reps=5000):
        """Return a list of bootstrapped means of differences."""
        # don't pickle the diffs as they are read-only, use a global to pass
        # it to workers
        global _diffs
        # because the samples are not independent, we calculate mean of
        # differences not a difference of means
        _diffs = self.data.iloc[:, pair.index1] -\
            self.data.iloc[:, pair.index2]

        job_size = os.cpu_count() * 10

        with mp.Pool() as pool:
            cent_tend = list(pool.imap_unordered(
                self._mean_of_random_sample,
                chain(repeat(job_size, reps//job_size), [reps % job_size])))
        return [i for sublist in cent_tend for i in sublist]

    def calc_diff_conf_int(self, pair, reps=5000, ci=0.95):
        """
        Bootstrap a confidence interval for the central tendency of differences

        :param TestPair pair: pairs to calculate the confidence interval
        :param int reps: how many bootstraping repetitions to perform
        :param float ci: confidence interval for the low and high estimate.
            0.95, i.e. "2 sigma", by default
        :return: tuple with low estimate, median, and high estimate of
            truncated mean of differences of observations
        """
        cent_tend = self._bootstrap_differences(pair, reps)

        return np.quantile(cent_tend, [(1-ci)/2, 0.5, 1-(1-ci)/2])

    def conf_interval_plot(self):
        """Generate the confidence inteval for differences between samples."""
        if not self.draw_conf_interval_plot:
            return

        reps = 5000
        data = pd.DataFrame()

        for i in range(1, len(self.class_names)):
            pair = TestPair(i, 0)
            diffs = self._bootstrap_differences(pair, reps)
            data['{}-0'.format(i)] = diffs

        with open(join(self.output, "bootstrapped_means.csv"), "w") as f:
            writer = csv.writer(f)
            writer.writerow(data.columns)
            writer.writerows(data.itertuples(index=False))

        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        ax = fig.add_subplot(1, 1, 1)
        ax.violinplot(data.T, widths=0.7, showmeans=True, showextrema=True)
        ax.set_xticks(list(range(len(data.columns)+1)))
        ax.set_xticklabels([' '] + list(data.columns))
        formatter = mpl.ticker.EngFormatter('s')
        ax.get_yaxis().set_major_formatter(formatter)

        ax.set_title("Confidence intervals for truncated mean of differences")
        ax.set_xlabel("Class pairs")
        ax.set_ylabel("Mean of differences")
        canvas.print_figure(join(self.output, "conf_interval_plot.png"),
                            bbox_inches="tight")

    def _write_individual_results(self):
        """Write results to report.csv"""
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
            worst_pair = None
            worst_p = None
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

                wilcox_p = wilcox_results[pair]
                row = [self.class_names[index1],
                       self.class_names[index2],
                       box_write,
                       wilcox_p
                       ]
                writer.writerow(row)

                p_vals.append(wilcox_p)

                if worst_pair is None or wilcox_p < worst_p:
                    worst_pair = pair
                    worst_p = wilcox_p

        return difference, p_vals, worst_pair, worst_p

    def _write_legend(self):
        """Write the legend.csv file."""
        legend_filename = join(self.output, "legend.csv")
        with open(legend_filename, "w") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['ID', 'Name'])
            for num, name in enumerate(self.class_names):
                writer.writerow([num, name])

    def _write_summary(self, difference, p_vals, worst_pair, worst_p):
        """Write the report.txt file and print summary."""
        report_filename = join(self.output, "report.csv")
        text_report_filename = join(self.output, "report.txt")
        with open(text_report_filename, 'w') as txt_file:
            _, p = stats.kstest(p_vals, 'uniform')
            txt = ("KS-test for uniformity of p-values from Wilcoxon "
                   "signed-rank test")
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            txt = "p-value: {}".format(p)
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            if p < 0.05:
                difference = 1

            txt = "Worst pair: {}({}), {}({})".format(
                worst_pair.index1,
                self.class_names[worst_pair.index1],
                worst_pair.index2,
                self.class_names[worst_pair.index2])
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            low, med, high = self.calc_diff_conf_int(worst_pair)
            # use 95% CI as that translates to 2 standard deviations, making
            # it easy to estimate higher CIs
            txt = "Median difference: {:.5e}s, 95% CI: {:.5e}s, {:.5e}s"\
                " (±{:.3e}s)".\
                format(med, low, high, (high-low)/2)
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            txt = "For detailed report see {}".format(report_filename)
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')
        return difference

    def generate_report(self):
        """
        Compiles a report consisting of statistical tests and plots.

        :return: int 0 if no difference was detected, 1 otherwise
        """
        # plot in separate processes so that the matplotlib memory leaks are
        # not cumulative, see https://stackoverflow.com/q/28516828/462370
        proc = mp.Process(target=self.box_plot)
        proc.start()
        proc.join()
        if proc.exitcode != 0:
            raise Exception("graph generation failed")
        proc = mp.Process(target=self.scatter_plot)
        proc.start()
        proc.join()
        if proc.exitcode != 0:
            raise Exception("graph generation failed")
        proc = mp.Process(target=self.ecdf_plot)
        proc.start()
        proc.join()
        if proc.exitcode != 0:
            raise Exception("graph generation failed")
        proc = mp.Process(target=self.conf_interval_plot)
        proc.start()
        proc.join()
        if proc.exitcode != 0:
            raise Exception("graph generation failed")
        self._write_legend()

        difference, p_vals, worst_pair, worst_p = \
            self._write_individual_results()

        difference = self._write_summary(difference, p_vals, worst_pair,
                                         worst_p)

        return difference


if __name__ == '__main__':
    ret = main()
    print("Analysis return value: {}".format(ret))
    sys.exit(ret)
