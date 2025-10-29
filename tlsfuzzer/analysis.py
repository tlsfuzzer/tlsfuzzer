#!/usr/bin/python
# -*- coding: utf-8 -*-

# Author: Jan Koscielniak, (c) 2020
# Author: Hubert Kario, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details


"""Analysis of timing information."""

from __future__ import print_function

import csv
import getopt
import sys
import math
import multiprocessing as mp
from threading import Event, Thread
import shutil
from itertools import chain
from os.path import join
from collections import namedtuple, defaultdict
from itertools import combinations, repeat, chain
import os
import time
import random

import numpy as np
from scipy import stats
import pandas as pd
import matplotlib as mpl
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas

from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.utils.progress_report import progress_report
from tlsfuzzer.utils.stats import skillings_mack_test, _slices
from tlsfuzzer.messages import div_ceil
from tlslite.utils.cryptomath import bytesToNumber


TestPair = namedtuple('TestPair', 'index1  index2')
mpl.use('Agg')


VERSION = 9


_diffs = None
_DATA = None


def help_msg():
    """Print help message"""
    print("""Usage: analysis [-o output]
 -o output         Directory where to place results (required)
                   and where timing.csv or measurements.csv is located
 --no-box-plot     Don't create the box_plot.png file
 --no-ecdf-plot    Don't create the ECDF graphs
 --no-scatter-plot Don't create the scatter plot graphs
 --no-conf-interval-plot Don't create the confidence interval graphs
 --no-box-test     Don't run the box test
 --no-wilcoxon-test Don't run the Wilcoxon signed rank test
 --no-t-test       Don't run the paired sample t-test
 --no-sign-test    [Hamming weight only] Don't run the sign test
 --no-le-sign-test Don't run the less-equal, greater-equal sign tests
 --no-sample-stats Don't calculate sample statistics (sample_stats.csv)
 --minimal-analysis Run just the pairwise sign tests, Friedman test, and
                   bootstrapping of confidence intervals (i.e. minimal amount
                   of calculation necessary to generate report.txt)
 --multithreaded-graph Create graph and calculate statistical tests at the
                   same time. Note: this increases memory usage of analysis by
                   a factor of 8.
 --clock-frequency freq Assume that the times in the file are not specified in
                   seconds but rather in clock cycles of a clock running at
                   frequency 'freq' specified in MHz. Use when the clock source
                   are the raw reads from the Time Stamp Counter register or
                   similar.
 --alpha num       Acceptable probability of a false positive. Default: 1e-5.
 --verbose         Print the current task
 --summary-only    Print only summary of the test, skip pairwise results
 --workers num     Number of worker processes to use for paralelizable
                   computation. More workers will finish analysis faster, but
                   will require more memory to do so. By default: number of
                   threads available on the system (`os.cpu_count()`).
 --status-delay num How often to print the status line for long-running
                   tasks in seconds.
 --status-newline  Use newline for printing status line, not carriage return,
                   works better with output redirection to file.
 --bit-size        Specifies that the program will analyze bit-size measurement
                   data from a measurements.csv file. A measurements.csv file
                   is expected as input and it should be in long-format
                   ("row id,column id,value").
 --Hamming-weight  Specified that the analysis will expect data for analysing
                   Hamming weight data from a measurements.csv file.
                   The measurements.csv is expected as input in the long-format
                   ("row id,column id,value")
 --no-smart-analysis By default when analysing bit size the script will compute
                   how much data are needed to calculate small confidence
                   interval to the 4th bit size and use only this number of
                   data (if available). This option disables this feature and
                   uses all the available data.
 --bit-size-desired-ci num The desired amount of ns (or lower) that the CIs
                   should have after the analysis up to recognition size
                   option. Used only with smart analysis. Default 1 ns.
 --measurements    Specifies the measurements file name that should be
                   analyzed.
                   The file must be present in the output dir. This flag only
                   works in combination the --bit-size flag.
 --skip-sanity     Skip sanity measurements from analysis (if any).
 --help            Display this message""")


def main():
    """Process arguments and start analysis."""
    output = None
    ecdf_plot = True
    scatter_plot = True
    conf_int_plot = True
    multithreaded_graph = False
    box_plot = True
    box_test = True
    le_sign_test = True
    sample_stats = True
    verbose = False
    clock_freq = None
    alpha = None
    workers = None
    delay = None
    carriage_return = None
    t_test = True
    wilcoxon_test = True
    sign_test = True
    bit_size_analysis = False
    smart_analysis = True
    summary_only = False
    bit_size_desired_ci = 1e-9
    measurements_filename = "measurements.csv"
    skip_sanity = False
    hamming_weight_analysis = False
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "o:",
                               ["help", "no-ecdf-plot", "no-scatter-plot",
                                "no-conf-interval-plot",
                                "no-t-test",
                                "no-sign-test",
                                "no-box-plot",
                                "no-box-test",
                                "no-wilcoxon-test",
                                "no-le-sign-test",
                                "no-sample-stats",
                                "minimal-analysis",
                                "multithreaded-graph",
                                "clock-frequency=",
                                "alpha=",
                                "workers=",
                                "status-delay=",
                                "status-newline",
                                "bit-size",
                                "no-smart-analysis",
                                "bit-size-desired-ci=",
                                "measurements=",
                                "skip-sanity",
                                "Hamming-weight",
                                "summary-only",
                                "verbose"])

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
        elif opt == "--no-sign-test":
            sign_test = False
        elif opt == "--no-t-test":
            t_test = False
        elif opt == "--no-box-plot":
            box_plot = False
        elif opt == "--no-box-test":
            box_test = False
        elif opt == "--no-wilcoxon-test":
            wilcoxon_test = False
        elif opt == "--no-le-sign-test":
            le_sign_test = False
        elif opt == "--no-sample-stats":
            sample_stats = False
        elif opt == "--minimal-analysis":
            ecdf_plot = False
            scatter_plot = False
            conf_int_plot = False
            box_plot = False
            box_test = False
            wilcoxon_test = False
            t_test = False
            le_sign_test = False
            sample_stats = False
        elif opt == "--multithreaded-graph":
            multithreaded_graph = True
        elif opt == "--clock-frequency":
            clock_freq = float(arg) * 1000000  # in MHz
        elif opt == "--alpha":
            alpha = float(arg)
        elif opt == "--workers":
            workers = int(arg)
        elif opt == "--verbose":
            verbose = True
        elif opt == "--summary-only":
            summary_only = True
        elif opt == "--status-delay":
            delay = float(arg)
        elif opt == "--status-newline":
            carriage_return = '\n'
        elif opt == "--bit-size":
            bit_size_analysis = True
        elif opt == "--Hamming-weight":
            hamming_weight_analysis = True
        elif opt == "--no-smart-analysis":
            smart_analysis = False
        elif opt == "--bit-size-desired-ci":
            bit_size_desired_ci = float(arg) * 1e-9
        elif opt == "--measurements":
            measurements_filename = arg
        elif opt == "--skip-sanity":
            skip_sanity = True

    if output:
        analysis = Analysis(output, ecdf_plot, scatter_plot, conf_int_plot,
                            multithreaded_graph, verbose, clock_freq, alpha,
                            workers, delay, carriage_return,
                            bit_size_analysis or hamming_weight_analysis,
                            smart_analysis, bit_size_desired_ci,
                            measurements_filename, skip_sanity, wilcoxon_test,
                            t_test, sign_test, box_plot, box_test,
                            le_sign_test, sample_stats, summary_only)

        ret = analysis.generate_report(
            bit_size=bit_size_analysis,
            hamming_weight=hamming_weight_analysis
        )

        return ret
    else:
        raise ValueError("Missing -o option!")


class Analysis(object):
    """Analyse extracted timing information from csv file."""

    def __init__(self, output, draw_ecdf_plot=True, draw_scatter_plot=True,
                 draw_conf_interval_plot=True, multithreaded_graph=False,
                 verbose=False, clock_frequency=None, alpha=None,
                 workers=None, delay=None, carriage_return=None,
                 bit_size_analysis=False, smart_bit_size_analysis=True,
                 bit_size_desired_ci=1e-9,
                 measurements_filename="measurements.csv", skip_sanity=False,
                 run_wilcoxon_test=True, run_t_test=True, run_sign_test=True,
                 draw_box_plot=True, run_box_test=True, run_le_sign_test=True,
                 gen_sample_stats=True, summary_only=False):
        self.verbose = verbose
        self.summary_only = summary_only
        self.output = output
        self.clock_frequency = clock_frequency
        self.class_names = []
        self.draw_ecdf_plot = draw_ecdf_plot
        self.draw_scatter_plot = draw_scatter_plot
        self.draw_conf_interval_plot = draw_conf_interval_plot
        self.draw_box_plot = draw_box_plot
        self.run_box_test = run_box_test
        self.run_wilcoxon_test = run_wilcoxon_test
        self.run_t_test = run_t_test
        self.run_sign_test = run_sign_test
        self.run_le_sign_test = run_le_sign_test
        self.gen_sample_stats = gen_sample_stats
        self.multithreaded_graph = multithreaded_graph
        self.workers = workers
        if alpha is None:
            self.alpha = 1e-5
        else:
            self.alpha = alpha
        self.delay = delay
        self.carriage_return = carriage_return
        self.measurements_filename = measurements_filename
        self.skip_sanity = skip_sanity

        if bit_size_analysis and smart_bit_size_analysis:
            self._bit_size_data_limit = 100000  # staring amount of samples
            self.bit_size_desired_ci = bit_size_desired_ci
        else:
            self._bit_size_data_limit = None

        self._k_sizes = None
        self._bit_size_data_used = None
        self._total_bit_size_data_used = 0
        self._sanity_data_points_used = 0

        if not bit_size_analysis:
            data = self.load_data()
            self.class_names = list(data)
        else:
            self._bit_size_sign_test = {}
            self._bit_size_wilcoxon_test = {}
            self._bit_size_bootstraping = {}
            self._hamming_weight_report = ""

            self._bit_size_methods = {
                "mean": "Mean",
                "median": "Median",
                "trim_mean_05": "Trimmed mean (5%)",
                "trim_mean_25": "Trimmed mean (25%)",
                "trim_mean_45": "Trimmed mean (45%)",
                "trimean": "Trimean"
            }

    @staticmethod
    def _check_if_workers_are_alive(workers):
        for p in workers:
            if not p.is_alive():
                raise RuntimeError(
                    "One of the workers was killed: {0}".format(p))

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

        if self.verbose:
            start_time = time.time()
            print("[i] Converting the data from text to binary format")

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
        if self.clock_frequency:
            chunk = chunk / self.clock_frequency
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
            if self.clock_frequency:
                chunk = chunk / self.clock_frequency
            timing_bin[rows_written:, :] = chunk.iloc[:, :]
            rows_written += len(chunk.index)

            del timing_bin

        with open(timing_bin_shape_path, "w") as f:
            writer = csv.writer(f)
            writer.writerow(["nrow", "ncol"])
            writer.writerow([rows_written, ncol])

        if self.verbose:
            print("[i] Conversion of the data to binary format done in {:.3}s"
                  .format(time.time() - start_time))

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

        if not self._bit_size_data_used:
            self._bit_size_data_used = len(data)

        return data

    @staticmethod
    def _box_test(data1, data2, quantile_start, quantile_end):
        """
        Internal configurable function to perform the box test.

        :param int interval1: index to data representing first sample
        :param int interval2: index to data representing second sample
        :param float quantile_start: starting quantile of the box
        :param float quantile_end: closing quantile of the box
        :return: None on no difference, int index of smaller sample if there
            is a difference
        """
        box1_start, box1_end = np.quantile(data1,
                                           [quantile_start, quantile_end])

        box2_start, box2_end = np.quantile(data2,
                                           [quantile_start, quantile_end])

        if box1_start == box2_start or box1_end == box2_end:
            # can return early because the intervals overlap
            return None

        intervals = {1: (box1_start, box1_end),
                     2: (box2_start, box2_end)}
        is_smaller = min(box1_start, box2_start) == box1_start
        smaller = 1 if is_smaller else 2
        bigger = 2 if smaller == 1 else 1

        if (intervals[smaller][0] < intervals[bigger][0] and
                intervals[smaller][1] < intervals[bigger][0]):
            if smaller == 1:
                return '<'
            else:
                return '>'
        return None

    def box_test(self):
        """Cross-test all classes with the box test"""
        if not self.run_box_test:
            return None
        if self.verbose:
            start_time = time.time()
            print("[i] Starting the box_test")

        results = self.mt_process(self._box_test, (0.03, 0.04))

        if self.verbose:
            print("[i] box_test done in {:.3}s".format(time.time()-start_time))

        return results

    @staticmethod
    def _wilcox_test(data1, data2):
        return stats.wilcoxon(data1, data2)[1]

    def wilcoxon_test(self):
        """Cross-test all classes with the Wilcoxon signed-rank test"""
        if not self.run_wilcoxon_test:
            return None
        if self.verbose:
            start_time = time.time()
            print("[i] Starting Wilcoxon signed-rank test")
        ret = self.mt_process(self._wilcox_test)
        if self.verbose:
            print("[i] Wilcoxon signed-rank test done in {:.3}s".format(
                time.time()-start_time))
        return ret

    @staticmethod
    def _rel_t_test(data1, data2):
        """Calculate ttest statistic, return p-value."""
        return stats.ttest_rel(data1, data2)[1]

    def rel_t_test(self):
        """Cross-test all classes using the t-test for dependent, paired
        samples."""
        if not self.run_t_test:
            return None
        if self.verbose:
            start_time = time.time()
            print("[i] Starting t-test for dependent, paired samples")
        ret = self.mt_process(self._rel_t_test)
        if self.verbose:
            print("[i] t-test for dependent, paired sample done in {:.3}s"
                  .format(time.time()-start_time))
        return ret

    # skip the coverage for this method as it doesn't have conditional
    # statements and is tested by mt_process() coverage (we don't see it
    # because coverage can't handle multiprocessing)
    def _mt_process_runner(self, params):  # pragma: no cover
        pair, sum_func, args = params
        data = self.load_data()
        index1, index2 = pair
        data1 = data.iloc[:, index1]
        data2 = data.iloc[:, index2]
        ret = sum_func(data1, data2, *args)
        return pair, ret

    def mt_process(self, sum_func, args=()):
        """Calculate sum_func values for all pairs of classes in data.

        Uses multiprocessing for calculation

        sum_func needs to accept two parameters, the values from first
        and second sample.

        Returns a dictionary with keys being the pairs of values and
        values being the returns from the sum_func
        """
        comb = list(combinations(list(range(len(self.class_names))), 2))
        job_size = max(len(comb) // os.cpu_count(), 1)
        with mp.Pool(self.workers) as pool:
            # while it's accessing a protected member of a python class,
            # it's a). been there for a long time (at least 2.7) and
            # b). it's because of a bug in multiprocessing module itself:
            # https://github.com/python/cpython/issues/96062
            # pylint: disable=protected-access
            workers = set(pool._pool)
            pvals = []

            for i in pool.imap_unordered(
                self._mt_process_runner,
                zip(comb, repeat(sum_func), repeat(args)),
                job_size
            ):
                pvals.append(i)

                workers.update(pool._pool)
                self._check_if_workers_are_alive(workers)
            # pylint: enable=protected-access

        results = dict(pvals)
        return results

    @staticmethod
    def _sign_test(data1, data2, med, alternative):
        diff = data2 - data1
        try:
            return stats.binomtest(sum(diff < med), sum(diff != med), p=0.5,
                                   alternative=alternative).pvalue
        except AttributeError:
            return stats.binom_test([sum(diff < med), sum(diff > med)], p=0.5,
                                    alternative=alternative)

    def sign_test(self, med=0.0, alternative="two-sided"):
        """
        Cross-test all classes using the sign test.

        med: expected median value

        alternative: the alternative hypothesis, "two-sided" by default,
            can be "less" or "greater". If called with "less" and returned
            p-value is much smaller than set alpha, then it's likely that the
            *second* sample in a pair is bigger than the first one. IOW,
            with "less" it tells the probability that second sample is smaller
            than the first sample.
        """
        if self.verbose:
            start_time = time.time()
            print("[i] Starting {} sign test".format(alternative))
        ret = self.mt_process(self._sign_test, (med, alternative))
        if self.verbose:
            print("[i] Sign test for {} done in {:.3}s".format(
                alternative, time.time()-start_time))
        return ret

    def friedman_test(self, result):
        """
        Test all classes using Friedman chi-square test.

        Note, as the scipy stats package uses a chisquare approximation, the
        test results are valid only when we have more than 10 samples.
        """
        if self.verbose:
            start_time = time.time()
            print("[i] Starting Friedman test")
        data = self.load_data()
        if len(self.class_names) < 3:
            result.put(None)
            return
        _, pval = stats.friedmanchisquare(
            *(data.iloc[:, i] for i in range(len(self.class_names))))
        if self.verbose:
            print("[i] Friedman test done in {:.3}s".format(
                time.time()-start_time))
        result.put(pval)

    def _calc_percentiles(self):
        data = self.load_data()
        try:
            quantiles_file_name = join(self.output, ".quantiles.tmp")
            shutil.copyfile(join(self.output, "timing.bin"),
                            quantiles_file_name)
            quant_in = np.memmap(quantiles_file_name,
                                 dtype=np.float64,
                                 mode="r+",
                                 shape=data.shape)
            percentiles = np.quantile(quant_in,
                                      [0.05, 0.25, 0.5, 0.75, 0.95],
                                      overwrite_input=True,
                                      axis=0)
            percentiles = pd.DataFrame(percentiles, columns=list(data),
                                       copy=False)
            return percentiles
        finally:
            del quant_in
            os.remove(quantiles_file_name)

    def box_plot(self):
        """Generate box plot for the test classes."""
        if not self.draw_box_plot:
            return None
        if self.verbose:
            start_time = time.time()
            print("[i] Generating the box plot")
        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        ax = fig.add_subplot(1, 1, 1)

        data = self.load_data()
        # a simpler alternative would use data.boxplot() but that
        # copies the data to the mathplot object
        # which means it doesn't keep it in a neat array.array, blowing up
        # the memory usage significantly
        # so calculate the values externally and just provide the computed
        # quantiles to the boxplot drawing function
        percentiles = self._calc_percentiles()
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
        ax.set_xticks(list(range(len(data.columns)+1)))
        ax.set_xticklabels([''] + list(range(len(data.columns))))

        ax.set_title("Box plot")
        ax.set_ylabel("Time")
        ax.set_xlabel("Class index")

        formatter = mpl.ticker.EngFormatter('s')
        ax.get_yaxis().set_major_formatter(formatter)

        canvas.print_figure(join(self.output, "box_plot.png"),
                            bbox_inches="tight")
        if self.verbose:
            print("[i] Box plot done in {:.3}s".format(time.time()-start_time))

    def scatter_plot(self):
        """Generate scatter plot showing how the measurement went."""
        if not self.draw_scatter_plot:
            return None
        if self.verbose:
            start_time = time.time()
            print("[i] Generating the scatter plots")
        data = self.load_data()

        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        ax = fig.add_subplot(1, 1, 1)
        ax.plot(data, ".", fillstyle='none', alpha=0.6)

        ax.set_title("Scatter plot")
        ax.set_ylabel("Time")
        ax.set_xlabel("Sample index")

        ax.set_yscale("log")

        formatter = mpl.ticker.EngFormatter('s')
        ax.get_yaxis().set_major_formatter(formatter)
        ax.get_yaxis().set_minor_formatter(formatter)

        self.make_legend(ax)

        canvas.print_figure(join(self.output, "scatter_plot.png"),
                            bbox_inches="tight")
        quant = np.quantile(data, [0.005, 0.95])
        # make sure the quantile point is visible on the graph
        quant[0] *= 0.98
        quant[1] *= 1.02
        ax.set_ylim(quant)
        canvas.print_figure(join(self.output, "scatter_plot_zoom_in.png"),
                            bbox_inches="tight")
        if self.verbose:
            print("[i] Scatter plots done in {:.3}s".format(
                time.time()-start_time))

    def diff_scatter_plot(self):
        """Generate scatter plot showing differences between samples."""
        if not self.draw_scatter_plot:
            return
        if self.verbose:
            start_time = time.time()
            print("[i] Generating scatter plots of differences")
        data = self.load_data()

        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        axes = fig.add_subplot(1, 1, 1)

        classnames = iter(data)
        base = next(classnames)
        base_data = data.loc[:, base]

        values = pd.DataFrame()
        for ctr, name in enumerate(classnames, start=1):
            diff = data.loc[:, name] - base_data
            values["{0}-0".format(ctr)] = diff

        axes.plot(values, ".", fillstyle='none', alpha=0.6)

        axes.set_title("Scatter plot of class differences")
        axes.set_ylabel("Time")
        axes.set_xlabel("Sample index")

        formatter = mpl.ticker.EngFormatter('s')
        axes.get_yaxis().set_major_formatter(formatter)

        axes.legend(values, ncol=6, loc='upper center',
                    bbox_to_anchor=(0.5, -0.15))
        canvas.print_figure(join(self.output, "diff_scatter_plot.png"),
                            bbox_inches="tight")
        quant = np.quantile(values, [0.25, 0.75])
        quant[0] *= 0.98
        quant[1] *= 1.02
        axes.set_ylim(quant)
        canvas.print_figure(join(self.output, "diff_scatter_plot_zoom_in.png"),
                            bbox_inches="tight")
        if self.verbose:
            print("[i] scatter plots of differences done in {:.3}s".format(
                time.time()-start_time))

    def ecdf_plot(self):
        """Generate ECDF plot comparing distributions of the test classes."""
        if not self.draw_ecdf_plot:
            return None
        if self.verbose:
            start_time = time.time()
            print("[i] Generating ECDF plots")
        data = self.load_data()
        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        ax = fig.add_subplot(1, 1, 1)
        for classname in data:
            values = data.loc[:, classname]
            values = np.sort(values)
            # provide only enough data points to plot a smooth graph
            nbins = 16 * fig.dpi * 10
            values = values[::max(len(values) // int(nbins), 1)]
            levels = np.linspace(1. / len(values), 1, len(values))
            ax.step(values, levels, where='post')
        self.make_legend(ax)
        ax.set_title("Empirical Cumulative Distribution Function")
        ax.set_xlabel("Time")
        ax.set_ylabel("Cumulative probability")

        formatter = mpl.ticker.EngFormatter('s')
        ax.get_xaxis().set_major_formatter(formatter)

        canvas.print_figure(join(self.output, "ecdf_plot.png"),
                            bbox_inches="tight")
        quant = np.quantile(values, [0.01, 0.95])
        quant[0] *= 0.98
        quant[1] *= 1.02
        ax.set_xlim(quant)
        canvas.print_figure(join(self.output, "ecdf_plot_zoom_in.png"),
                            bbox_inches="tight")
        if self.verbose:
            print("[i] ECDF plots done in {:.3}s".format(
                time.time()-start_time))

    def diff_ecdf_plot(self):
        """Generate ECDF plot of differences between test classes."""
        if not self.draw_ecdf_plot:
            return
        if self.verbose:
            start_time = time.time()
            print("[i] Generating ECDF plots of differences")
        data = self.load_data()
        classnames = iter(data)
        base = next(classnames)
        base_data = data.loc[:, base]

        # parameters for the zoomed-in graphs of ecdf
        zoom_params = OrderedDict([("", (0, 1)),
                                   ("98", (0.01, 0.99)),
                                   ("33", (0.33, 0.66)),
                                   ("10", (0.45, 0.55))])
        zoom_values = OrderedDict((name, [float("inf"), float("-inf")])
                                  for name in zoom_params.keys())

        # calculate the params for ECDF graphs
        for classname in classnames:
            values = data.loc[:, classname]
            values = values-base_data

            quantiles = np.quantile(values, list(chain(*zoom_params.values())))
            quantiles = iter(quantiles)
            for low, high, name in \
                    zip(quantiles, quantiles, zoom_params.keys()):
                zoom_values[name][0] = min(zoom_values[name][0], low)
                zoom_values[name][1] = max(zoom_values[name][1], high)

        for name, quantiles, zoom_val in \
                zip(zoom_params.keys(), zoom_params.values(),
                    zoom_values.values()):
            fig = Figure(figsize=(16, 12))
            canvas = FigureCanvas(fig)
            axes = fig.add_subplot(1, 1, 1)

            # rewind the iterator
            classnames = iter(data)
            next(classnames)

            for classname in classnames:
                # calculate the ECDF
                values = data.loc[:, classname]
                values = np.sort(values-base_data)
                # provide only enough data points to plot a smooth graph
                nbins = 16 * fig.dpi
                min_pos = int(len(values) * quantiles[0])
                max_pos = int(math.ceil(len(values) * quantiles[1]))
                values = values[min_pos:max_pos:
                                max((max_pos-min_pos) // int(nbins), 1)]
                levels = np.linspace(quantiles[0], quantiles[1],
                                     len(values))
                axes.step(values, levels, where='post')

            fig.legend(list("{0}-0".format(i)
                            for i in range(1, len(list(values)))),
                       ncol=6,
                       loc='upper center',
                       bbox_to_anchor=(0.5, -0.05))
            axes.set_title("Empirical Cumulative Distribution Function of "
                           "class differences")
            axes.set_xlabel("Time")
            axes.set_ylabel("Cumulative probability")

            formatter = mpl.ticker.EngFormatter('s')
            axes.get_xaxis().set_major_formatter(formatter)

            if not name:
                canvas.print_figure(join(self.output, "diff_ecdf_plot.png"),
                                    bbox_inches="tight")
            else:
                axes.set_ylim(quantiles)
                # make the bounds a little weaker so that the extreme positions
                # are visible of graph too
                axes.set_xlim([zoom_val[0]*0.98, zoom_val[1]*1.02])
                canvas.print_figure(join(self.output,
                                         "diff_ecdf_plot_zoom_in_{0}.png"
                                         .format(name)),
                                    bbox_inches="tight")

        if self.verbose:
            print("[i] ECDF plots of differences done in {:.3}s".format(
                time.time()-start_time))

    def make_legend(self, fig):
        """Generate common legend for plots that need it."""
        data = self.load_data()
        header = list(range(len(list(data))))
        fig.legend(header,
                   ncol=6,
                   loc='upper center',
                   bbox_to_anchor=(0.5, -0.15)
                   )

    @staticmethod
    def _cent_tend_of_random_sample(reps=100):
        """
        Calculate mean, median, trimmed means (5%, 25%, 45%) and trimean with
        bootstrapping.
        """
        ret = []
        global _diffs
        diffs = _diffs

        for _ in range(reps):
            boot = np.random.choice(diffs, replace=True, size=len(diffs))

            q1, median, q3 = np.quantile(boot, [0.25, 0.5, 0.75])
            # use tuple instead of a dict because tuples are much quicker
            # to instantiate
            ret.append((np.mean(boot, 0),
                        median,
                        stats.trim_mean(boot, 0.05, 0),
                        stats.trim_mean(boot, 0.25, 0),
                        stats.trim_mean(boot, 0.45, 0),
                        (q1+2*median+q3)/4))
        return ret

    @staticmethod
    def _import_diffs(diffs):
        global _diffs
        _diffs = diffs

    def _bootstrap_differences(self, pair, reps=5000, status=None):
        """Return a list of bootstrapped central tendencies of differences."""
        # don't pickle the diffs as they are read-only, use a global to pass
        # it to workers
        global _diffs
        # because the samples are not independent, we calculate mean of
        # differences not a difference of means
        data = self.load_data()
        index1, index2 = pair
        _diffs = data.iloc[:, index2] -\
            data.iloc[:, index1]

        job_count = os.cpu_count() * 4
        job_size = max(reps // job_count, 1)

        keys = ("mean", "median", "trim_mean_05", "trim_mean_25",
                "trim_mean_45", "trimean")

        ret = dict((k, list()) for k in keys)

        with mp.Pool(self.workers, initializer=self._import_diffs,
                     initargs=(_diffs,)) as pool:
            # while it's accessing a protected member of a python class,
            # it's a). been there for a long time (at least 2.7) and
            # b). it's because of a bug in multiprocessing module itself:
            # https://github.com/python/cpython/issues/96062
            # pylint: disable=protected-access
            workers = set(pool._pool)

            cent_tend = pool.imap_unordered(
                self._cent_tend_of_random_sample,
                chain(repeat(job_size, reps // job_size), [reps % job_size]))

            for values in cent_tend:
                # handle reps % job_size == 0
                if not values:
                    continue
                if status:
                    status[0] += len(values)
                # transpose the results so that they can be added to lists
                chunk = list(map(list, zip(*values)))
                for key, i in zip(keys, range(len(keys))):
                    ret[key].extend(chunk[i])

                workers.update(pool._pool)
                self._check_if_workers_are_alive(workers)
            # pylint: enable=protected-access

        _diffs = None
        return ret

    def _calc_exact_values(self, diff):
        mean = np.mean(diff)
        q1, median, q3 = np.quantile(diff, [0.25, 0.5, 0.75])
        trim_mean_05 = stats.trim_mean(diff, 0.05, 0)
        trim_mean_25 = stats.trim_mean(diff, 0.25, 0)
        trim_mean_45 = stats.trim_mean(diff, 0.45, 0)
        trimean = (q1 + 2*median + q3)/4

        return {"mean": mean, "median": median,
                "trim_mean_05": trim_mean_05,
                "trim_mean_25": trim_mean_25,
                "trim_mean_45": trim_mean_45,
                "trimean": trimean}

    def calc_diff_conf_int(self, pair, reps=5000, ci=0.95):
        """
        Bootstrap a confidence interval for the central tendencies of
        differences.

        :param TestPair pair: identification of samples to calculate the
            confidence interval
        :param int reps: how many bootstraping repetitions to perform
        :param float ci: confidence interval for the low and high estimate.
            0.95, i.e. "2 sigma", by default
        :return: dictionary of tuples with low estimate, estimate, and high
            estimate of mean, median, trimmed mean (5%, 25%, 45%) and trimean
            of differences of observations
        """
        status = None
        if self.verbose:
            start_time = time.time()
            print("[i] Calculating confidence intervals of central tendencies")
            status = [0, reps, Event()]
            kwargs = {}
            kwargs['unit'] = ' bootstraps'
            kwargs['delay'] = self.delay
            kwargs['end'] = self.carriage_return
            progress = Thread(target=progress_report, args=(status,),
                              kwargs=kwargs)
            progress.start()

        try:
            cent_tend = self._bootstrap_differences(pair, reps, status=status)
        finally:
            if self.verbose:
                status[2].set()
                progress.join()
                print()

        data = self.load_data()
        diff = data.iloc[:, pair[1]] - data.iloc[:, pair[0]]
        exact_values = self._calc_exact_values(diff)

        quantiles = [(1-ci)/2, 1-(1-ci)/2]
        ret = {}
        for key, value in exact_values.items():
            calc_quant = np.quantile(cent_tend[key], quantiles)
            ret[key] = (calc_quant[0], value, calc_quant[1])
        if self.verbose:
            print("[i] Confidence intervals of central tendencies done in "
                  "{:.3}s".format(time.time()-start_time))
        return ret

    def conf_interval_plot(self):
        """Generate the confidence inteval for differences between samples."""
        if not self.draw_conf_interval_plot:
            return
        if self.verbose:
            start_time = time.time()
            print("[i] Graphing confidence interval plots")

        reps = 5000
        boots = {"mean": pd.DataFrame(),
                 "median": pd.DataFrame(),
                 "trim mean (5%)": pd.DataFrame(),
                 "trim mean (25%)": pd.DataFrame(),
                 "trim mean (45%)": pd.DataFrame(),
                 "trimean": pd.DataFrame()}

        status = None
        if self.verbose:
            status = [0, reps * (len(self.class_names) - 1), Event()]
            kwargs = {}
            kwargs['unit'] = ' bootstraps'
            kwargs['delay'] = self.delay
            kwargs['end'] = self.carriage_return
            progress = Thread(target=progress_report, args=(status, ),
                              kwargs=kwargs)
            progress.start()

        try:
            for i in range(1, len(self.class_names)):
                pair = TestPair(0, i)
                diffs = self._bootstrap_differences(pair, reps, status)

                boots["mean"]['{}-0'.format(i)] = diffs["mean"]
                boots["median"]['{}-0'.format(i)] = diffs["median"]
                boots["trim mean (5%)"]['{}-0'.format(i)] = \
                    diffs["trim_mean_05"]
                boots["trim mean (25%)"]['{}-0'.format(i)] = \
                    diffs["trim_mean_25"]
                boots["trim mean (45%)"]['{}-0'.format(i)] = \
                    diffs["trim_mean_45"]
                boots["trimean"]['{}-0'.format(i)] = diffs["trimean"]
        finally:
            if self.verbose:
                status[2].set()
                progress.join()
                print()

        for name, data in boots.items():
            fig = Figure(figsize=(16, 12))
            canvas = FigureCanvas(fig)
            ax = fig.add_subplot(1, 1, 1)
            ax.violinplot(data, widths=0.7, showmeans=True, showextrema=True)
            ax.set_xticks(list(range(len(data.columns)+1)))
            ax.set_xticklabels([' '] + list(data.columns))
            formatter = mpl.ticker.EngFormatter('s')
            ax.get_yaxis().set_major_formatter(formatter)

            ax.set_title("Confidence intervals for {0} of differences"
                         .format(name))
            ax.set_xlabel("Class pairs")
            ax.set_ylabel("{0} of differences".format(name))

            formatter = mpl.ticker.EngFormatter('s')
            ax.get_yaxis().set_major_formatter(formatter)

            if name == "trim mean (5%)":
                name = "trim_mean_05"
            elif name == "trim mean (25%)":
                name = "trim_mean_25"
            elif name == "trim mean (45%)":
                name = "trim_mean_45"

            with open(join(self.output,
                           "bootstrapped_{0}.csv".format(name)),
                      "w") as f:
                writer = csv.writer(f)
                writer.writerow(data.columns)
                writer.writerows(data.itertuples(index=False))

            canvas.print_figure(join(self.output,
                                     "conf_interval_plot_{0}.png"
                                     .format(name)),
                                bbox_inches="tight")
        if self.verbose:
            print("[i] Confidence interval plots done in {:.3}s".format(
                time.time()-start_time))

    @staticmethod
    def _desc_stats(data1, data2):
        diff = data2 - data1

        diff_stats = {}
        diff_stats["mean"] = np.mean(diff)
        diff_stats["SD"] = np.std(diff)
        quantiles = np.quantile(diff, [0.25, 0.5, 0.75])
        diff_stats["median"] = quantiles[1]
        diff_stats["IQR"] = quantiles[2] - quantiles[0]
        diff_stats["MAD"] = stats.median_abs_deviation(diff)
        return diff_stats

    def desc_stats(self):
        """Calculate the descriptive statistics for sample differences."""
        if self.verbose:
            start_time = time.time()
            print("[i] Calculating descriptive statistics of sample "
                  "differences")

        results = self.mt_process(self._desc_stats)

        if self.verbose:
            print("[i] Descriptive statistics of sample differences done in "
                  "{:.3}s".format(time.time()-start_time))
        return results

    @staticmethod
    def _write_stats(name, low, med, high, txt_file):
        txt = "{} of differences: {:.5e}s, 95% CI: {:.5e}s, {:5e}s (±{:.3e}s)"\
            .format(name, med, low, high, (high-low)/2)
        print(txt)
        txt_file.write(txt + "\n")

    def _write_individual_results(self):
        """Write results to report.csv"""
        if self.verbose:
            start_time = time.time()
            print("[i] Starting calculation of individual results")
        difference = 0
        # create a report with statistical tests
        box_results = self.box_test()
        wilcox_results = self.wilcoxon_test()
        sign_results = self.sign_test()
        if self.run_le_sign_test:
            sign_less_results = self.sign_test(alternative="less")
            sign_greater_results = self.sign_test(alternative="greater")
        else:
            sign_less_results = None
            sign_greater_results = None
        ttest_results = self.rel_t_test()
        desc_stats = self.desc_stats()

        report_filename = join(self.output, "report.csv")
        p_vals = []
        sign_p_vals = []
        with open(report_filename, 'w') as file:
            writer = csv.writer(file)
            columns = ["Class 1", "Class 2"]
            if self.run_box_test:
                columns += ["Box test"]
            if self.run_wilcoxon_test:
                columns += ["Wilcoxon signed-rank test"]
            columns += ["Sign test"]
            if self.run_le_sign_test:
                columns += ["Sign test less", "Sign test greater"]
            if self.run_t_test:
                columns += ["paired t-test"]
            columns += ["mean", "SD", "median", "IQR", "MAD"]
            writer.writerow(columns)
            worst_pair = None
            worst_p = None
            worst_median_difference = None
            for pair, result in sorted(sign_results.items()):
                index1, index2 = pair
                diff_stats = desc_stats[pair]
                box_write = "="
                if self.run_box_test:
                    result = box_results[pair]
                    if result:
                        if not self.summary_only:
                            print("Box test {0} vs {1}: {0} {2} {1}".format(
                                index1,
                                index2,
                                result))
                        box_write = result
                    else:
                        if not self.summary_only:
                            print("Box test {} vs {}: No difference".format(
                                index1,
                                index2))
                if self.run_wilcoxon_test and not self.summary_only:
                    print("Wilcoxon signed-rank test {} vs {}: {:.3}"
                          .format(index1, index2, wilcox_results[pair]))
                if not self.summary_only:
                    print("Sign test {} vs {}: {:.3}"
                          .format(index1, index2, sign_results[pair]))
                if self.run_le_sign_test:
                    if not self.summary_only:
                        print("Sign test, probability that {1} < {0}: {2:.3}"
                              .format(index1, index2, sign_less_results[pair]))
                        print("Sign test, probability that {1} > {0}: {2:.3}"
                              .format(index1, index2,
                                      sign_greater_results[pair]))
                    if sign_results[pair] > 0.05:
                        sign_test_relation = "="
                    elif sign_less_results[pair] > sign_greater_results[pair]:
                        sign_test_relation = "<"
                    else:
                        sign_test_relation = ">"
                if not self.summary_only:
                    print("Sign test interpretation: {} {} {}"
                          .format(index2, sign_test_relation, index1))
                if self.run_t_test and not self.summary_only:
                    print("Dependent t-test for paired samples {} vs {}: {:.3}"
                          .format(index1, index2, ttest_results[pair]))
                if not self.summary_only:
                    print("{} vs {} stats: mean: {:.3}, SD: {:.3}, "
                          "median: {:.3}, "
                          "IQR: {:.3}, MAD: {:.3}".format(
                              index1, index2, diff_stats["mean"],
                              diff_stats["SD"],
                              diff_stats["median"], diff_stats["IQR"],
                              diff_stats["MAD"]))

                # If either of the pairwise tests shows a small p-value with
                # Bonferroni correction consider it a possible side-channel
                if (self.run_wilcoxon_test and
                    wilcox_results[pair] < self.alpha / len(sign_results)) or \
                    sign_results[pair] < self.alpha / len(sign_results) or\
                    (self.run_t_test and
                     ttest_results[pair] < self.alpha / len(sign_results)):
                    difference = 1

                if self.run_wilcoxon_test:
                    wilcox_p = wilcox_results[pair]
                else:
                    wilcox_p = 1
                sign_p = sign_results[pair]
                if self.run_t_test:
                    ttest_p = ttest_results[pair]
                else:
                    ttest_p = 1
                row = [self.class_names[index1],
                       self.class_names[index2]]
                if self.run_box_test:
                    row.append(box_write)
                if self.run_wilcoxon_test:
                    row.append(wilcox_p)
                row.append(sign_p)
                if self.run_le_sign_test:
                    row.extend([sign_less_results[pair],
                                sign_greater_results[pair]])
                if self.run_t_test:
                    row.append(ttest_p)
                row.extend([
                           diff_stats["mean"],
                           diff_stats["SD"],
                           diff_stats["median"],
                           diff_stats["IQR"],
                           diff_stats["MAD"]
                           ])
                writer.writerow(row)

                p_vals.append(wilcox_p)
                sign_p_vals.append(sign_p)
                median_difference = abs(diff_stats["median"])

                if worst_pair is None or sign_p < worst_p or \
                        worst_median_difference is None or \
                        worst_median_difference < median_difference:
                    worst_pair = pair
                    worst_p = sign_p
                    worst_median_difference = median_difference

        if self.verbose:
            print("[i] Calculation of individual results done in {:.3}s"
                  .format(time.time()-start_time))

        return difference, p_vals, sign_p_vals, worst_pair

    def _write_legend(self):
        """Write the legend.csv file."""
        legend_filename = join(self.output, "legend.csv")
        with open(legend_filename, "w") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['ID', 'Name'])
            for num, name in enumerate(self.class_names):
                writer.writerow([num, name])

    def _write_sample_stats(self):
        """Write summary statistics of samples to sample_stats.csv file."""
        if not self.gen_sample_stats:
            return None
        if self.verbose:
            start_time = time.time()
            print("[i] Writing summary statistics of samples to file")
        data = self.load_data()
        stats_filename = join(self.output, "sample_stats.csv")
        with open(stats_filename, "w") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['Name', 'mean', 'median', 'MAD'])
            for num, name in enumerate(self.class_names):
                sample = data.iloc[:, num]
                writer.writerow([
                    name,
                    np.mean(sample),
                    np.median(sample),
                    stats.median_abs_deviation(sample)])

        if self.verbose:
            print("[i] Summary statistics of samples written to file in {:.3}s"
                  .format(time.time()-start_time))

    def _graph_hist_over_time(self, data, min_lvl, max_lvl, title, file_name):

        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        dpi = fig.dpi

        width_ppx = 16 * dpi
        height_ppx = 12 * dpi

        sample_size = len(data)

        # make sure the individual histograms have something to work with
        # but make them at least 2 pixels wide
        bucket_width = int(max(256, div_ceil(sample_size, (width_ppx / 2))))
        bucket_count = div_ceil(sample_size, bucket_width)

        # make the rows 2 pixels high
        bins_count = int(height_ppx / 2)
        bin_width = (max_lvl - min_lvl) / bins_count

        x_indexes = list(range(
            bucket_width // 2,
            # we're setting the indexes in the middle of the bin, ensure that
            # they are in the list
            sample_size + (bucket_width // 2) - 1,
            bucket_width))
        y_indexes = [min_lvl + i * bin_width for i in range(bins_count)]
        assert len(x_indexes) == bucket_count, (len(x_indexes), bucket_count)
        assert len(y_indexes) == bins_count, (len(y_indexes), bins_count)

        data_hists = pd.DataFrame(
            np.full((bins_count, bucket_count), float("NaN")),
            columns=x_indexes,
            index=y_indexes)

        for name, start, end in zip(
                x_indexes,
                range(0, sample_size, bucket_width),
                range(bucket_width, sample_size, bucket_width)):
            bucket = data[start:end]
            hist = np.histogram(
                bucket, bins=bins_count,
                range=(min_lvl, max_lvl))[0]
            data_hists[name] = hist

        axes = fig.add_subplot(1, 1, 1)
        pcm = axes.pcolormesh(x_indexes, y_indexes, data_hists,
                              shading="auto")
        axes.set_title(title)
        axes.set_xlabel("Index")
        axes.set_ylabel("Time")

        formatter = mpl.ticker.EngFormatter('s')
        axes.get_yaxis().set_major_formatter(formatter)

        cbar = fig.colorbar(pcm, ax=axes)
        cbar.set_label("Counts")

        canvas.print_figure(join(self.output,
                                 file_name),
                            bbox_inches="tight")

    def graph_worst_pair(self, pair):
        """Create heatmap plots for the most dissimilar sample pair"""
        if self.verbose:
            start_time = time.time()
            print("[i] Start graphing the worst pair data")
        data = self.load_data()
        index1, index2 = pair

        data1 = data.iloc[:, index1]
        data2 = data.iloc[:, index2]

        # first plot the samples individually

        # we want the same scale on both graphs, so use common min and max
        global_min = min(min(data1), min(data2))
        global_max = max(max(data1), max(data2))
        # same for zoomed-in data
        # use asymmetric quantiles as timing isn't symmetric (for one, can't
        # have negative response times)
        data1_q1, data1_q3 = np.quantile(data1, [0.005, 0.95])
        data2_q1, data2_q3 = np.quantile(data2, [0.005, 0.95])
        global_q1 = min(data1_q1, data2_q1)
        global_q3 = max(data1_q3, data2_q3)

        self._graph_hist_over_time(
            data1, global_min, global_max,
            "Sample {} heatmap".format(index1),
            "sample_{}_heatmap.png".format(index1))
        self._graph_hist_over_time(
            data1, global_q1, global_q3,
            "Sample {} heatmap".format(index1),
            "sample_{}_heatmap_zoom_in.png".format(index1))
        self._graph_hist_over_time(
            data2, global_min, global_max,
            "Sample {} heatmap".format(index2),
            "sample_{}_heatmap.png".format(index2))
        self._graph_hist_over_time(
            data2, global_q1, global_q3,
            "Sample {} heatmap".format(index2),
            "sample_{}_heatmap_zoom_in.png".format(index2))
        if len(data1) > 100000:
            self._graph_hist_over_time(
                data1[:100000], global_q1, global_q3,
                "Sample {} heatmap".format(index1),
                "sample_{}_partial_heatmap_zoom_in.png".format(index1))
            self._graph_hist_over_time(
                data2[:100000], global_q1, global_q3,
                "Sample {} heatmap".format(index2),
                "sample_{}_partial_heatmap_zoom_in.png".format(index2))

        # and then plot the differences

        diff = data2 - data1
        diff_min, diff_q1, diff_q3, diff_max = \
            np.quantile(diff, [0, 0.05, 0.95, 1])

        self._graph_hist_over_time(
            diff, diff_min, diff_max,
            "Difference plot of ({}-{})".format(index2, index1),
            "worst_pair_diff_heatmap.png")
        self._graph_hist_over_time(
            diff, diff_q1, diff_q3,
            "Difference plot of ({}-{})".format(index2, index1),
            "worst_pair_diff_heatmap_zoom_in.png")
        if len(data1) > 100000:
            self._graph_hist_over_time(
                diff[:100000], diff_q1, diff_q3,
                "Difference plot of ({}-{})".format(index2, index1),
                "worst_pair_diff_partial_heatmap_zoom_in.png")

        if self.verbose:
            print("[i] Worst pair data graphed in {:.3}s".format(
                time.time()-start_time))

    def _write_summary(self, difference, p_vals, sign_p_vals, worst_pair,
                       friedman_p, worst_pair_conf_int):
        """Write the report.txt file and print summary."""
        report_filename = join(self.output, "report.csv")
        text_report_filename = join(self.output, "report.txt")
        with open(text_report_filename, 'w') as txt_file:
            txt_file.write(
                "tlsfuzzer analyse.py version {0} analysis\n"
                .format(VERSION))

            txt = ("Sign test mean p-value: {0:.4}, median p-value: {1:.4}, "
                   "min p-value: {2:.4}"
                   .format(np.mean(sign_p_vals), np.median(sign_p_vals),
                           np.min(sign_p_vals)))
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            txt = "Friedman test (chisquare approximation) for all samples"
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            txt = "p-value: {}".format(friedman_p)
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')
            if friedman_p is not None and friedman_p < self.alpha:
                difference = 1

            txt = "Worst pair: {}({}), {}({})".format(
                worst_pair[0],
                self.class_names[worst_pair[0]],
                worst_pair[1],
                self.class_names[worst_pair[1]])
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            diff_conf_int = worst_pair_conf_int
            # use 95% CI as that translates to 2 standard deviations, making
            # it easy to estimate higher CIs
            for name, key in (("Mean", "mean"), ("Median", "median"),
                              ("Trimmed mean (5%)", "trim_mean_05"),
                              ("Trimmed mean (25%)", "trim_mean_25"),
                              ("Trimmed mean (45%)", "trim_mean_45"),
                              ("Trimean", "trimean")):
                self._write_stats(
                    name,
                    diff_conf_int[key][0], diff_conf_int[key][1],
                    diff_conf_int[key][2], txt_file)

            # when comparing a data set with just 2 samples then
            # Friedman test doesn't work, but in practice it's equivalent
            # to the sign test
            if friedman_p is None:
                friedman_p = np.min(sign_p_vals)

            if friedman_p < 1e-9:
                explanation = (
                    "Definite side-channel detected, "
                    "implementation is VULNERABLE")
            elif friedman_p < 1e-5:
                explanation = (
                    "Results suggesting side-channel found, "
                    "collecting more data necessary for confirmation")
            else:
                small_cis = list(
                    (diff_conf_int[key][2]-diff_conf_int[key][0])/2
                    for key in
                    ["mean", "median", "trim_mean_05", "trim_mean_25",
                     "trim_mean_45"])
                if max(small_cis) == 0:
                    explanation = (
                        "All 95% CIs are equal 0. Too small sammple"
                        " or too low clock resolution for the measurement.")
                    print("ERROR: " + explanation)
                else:
                    # when measuring values below clock frequency
                    # or very small pieces of code with high resolution clock
                    # it may cause the 95% CI to equal 0.0; that's not a
                    # realistic value so ignore it
                    # (for median it would be nice to actually check if we're
                    # not in the vicinity of the clock resolution, and ignore
                    # median then, but that's much more complex so don't do it
                    # for now)
                    small_ci = min(i for i in small_cis if i != 0)
                    if small_ci < 1e-10:
                        explanation = (
                            "Implementation verified as not "
                            "providing a timing side-channel signal")
                    elif small_ci < 1e-9:
                        explanation = (
                            "Implementation most likely not "
                            "providing a timing side-channel signal")
                    elif small_ci < 1e-2:
                        explanation = (
                            "Large confidence intervals detected, "
                            "collecting more data necessary. Side channel "
                            "leakage smaller than {0:.3e}s is possible".format(
                                small_ci))
                    else:
                        explanation = (
                            "Very large confidence intervals detected. "
                            "Incorrect or missing --clock-frequency option?")

            txt = "Layperson explanation: {0}".format(explanation)
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            txt = "For detailed report see {}".format(report_filename)
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')
        return difference

    def _start_thread(self, method, err_desc):
        """Start a thread, wait for end with self.multithreaded_graph set."""
        proc = mp.Process(target=method)
        proc.start()
        if not self.multithreaded_graph:
            self._stop_thread(proc, err_desc)
        return (proc, err_desc)

    @staticmethod
    def _stop_thread(proc, err_desc):
        """Wait for thread completion, raise Exception on error."""
        proc.join()
        if proc.exitcode != 0:
            raise Exception(err_desc)

    def _stop_all_threads(self, threads):
        """Wait for completion of threads, raise Exception on error."""
        if not self.multithreaded_graph:
            return

        errors = []

        for proc, err_desc in threads:
            try:
                self._stop_thread(proc, err_desc)
            except Exception as e:
                errors.append(str(e))

        if errors:
            raise Exception(str(errors))

    def _long_format_to_binary(self, name, name_bin):
        """Turns csv with long format data to binary"""
        measurements_csv_path = name
        measurements_bin_path = name_bin
        measurements_bin_shape_path = measurements_bin_path + ".shape"

        if os.path.isfile(measurements_bin_path) and \
                os.path.isfile(measurements_bin_shape_path) and \
                os.path.isfile(measurements_csv_path) and \
                os.path.getmtime(measurements_csv_path) < \
                os.path.getmtime(measurements_bin_path):  # pragma: no cover
            return

        if self.verbose:
            start_time = time.time()
            print("[i] Converting the data from text to binary format")

        csv_reader = pd.read_csv(measurements_csv_path,
                                 dtype=[('block', np.int64),
                                        ('group', np.int32),
                                        ('value', np.float64)],
                                 names=['block', 'group', 'value'],
                                 chunksize=1024*1024*8,
                                 header=None,
                                 iterator=True)

        row_written = 0

        chunk = next(csv_reader)
        measurements_bin = np.memmap(measurements_bin_path,
                                     dtype=[('block', np.dtype('i8')),
                                            ('group', np.dtype('i2')),
                                            ('value', np.dtype('f8'))],
                                     mode="w+",
                                     shape=(len(chunk.index), 1),
                                     order="C")

        measurements_bin['block'] = chunk.iloc[:, 0:1]
        measurements_bin['group'] = chunk.iloc[:, 1:2]
        measurements_bin['value'] = chunk.iloc[:, 2:3]

        row_written += len(chunk.index)

        del measurements_bin

        for chunk in csv_reader:
            measurements_bin = np.memmap(measurements_bin_path,
                                         dtype=[('block', np.dtype('i8')),
                                                ('group', np.dtype('i2')),
                                                ('value', np.dtype('f8'))],
                                         mode="r+",
                                         shape=(row_written + len(chunk.index),
                                                1),
                                         order="C")
            measurements_bin['block'][row_written:, :] = chunk.iloc[:, 0:1]
            measurements_bin['group'][row_written:, :] = chunk.iloc[:, 1:2]
            measurements_bin['value'][row_written:, :] = chunk.iloc[:, 2:3]
            row_written += len(chunk.index)
            del measurements_bin

        with open(measurements_bin_shape_path, "w") as shape_f:
            shape_f.write("{0},3\n".format(row_written))

        if self.verbose:
            print("[i] Conversion to binary format done in {:.3}s".format(
                time.time() - start_time))

    def _remove_suffix(self, string, suffix):
        '''
        Removes the chosen suffix of from the string if exists otherwise does
        nothing to the original string
        '''
        new_string = string

        try:
            new_string = string.removesuffix(suffix)
        except AttributeError:
            suffix_len = len(suffix)
            if string[-suffix_len:] == suffix:
                new_string = string[:-suffix_len]

        return new_string

    def skillings_mack_test(self, measurements_bin_path):
        """
        Calculate the p-value of the Skillings-Mack test for the Hamming weight
        data.
        """

        data = np.memmap(measurements_bin_path,
                         dtype=[('block', np.dtype('i8')),
                                ('group', np.dtype('i2')),
                                ('value', np.dtype('f8'))],
                         mode="r")

        try:
            blocks = data['block']
            groups = data['group']
            values = data['value']

            status = None
            if self.verbose:
                print("[i] Calculating Skillings-Mack test")
                start_time = time.time()
                status = [0, len(blocks), Event()]
                kwargs = dict()
                kwargs['unit'] = " obs"
                kwargs['delay'] = self.delay
                kwargs['end'] = self.carriage_return
                progress = Thread(target=progress_report, args=(status,),
                                  kwargs=kwargs)
                progress.start()

            try:
                sm_test = skillings_mack_test(values, groups, blocks,
                                              # because the blocks are sorted,
                                              # and the first instance of the
                                              # biggest k is the base value,
                                              # while the second instance is
                                              # the sanity check, in case of
                                              # duplicates we want to use first
                                              # value
                                              "first",
                                              status=status)
            finally:
                if self.verbose:
                    status[2].set()
                    progress.join()
                    print()
                    print("[i] Skillings-Mack test done in {:.3}s".format(
                        time.time() - start_time))
                    print("[i] Skillings-Mack p-value: {0:.6e}".format(
                        sm_test.p_value))

        finally:
            del data

        return sm_test.p_value

    def _bit_size_come_to_verdict(self, analysis_ret_val,
                                  skillings_mack_pvalue):
        """Comes to a verdict if implementation is vulnerable"""
        explanation = None
        difference = 1

        if analysis_ret_val != 0:
            explanation = ("Definite side-channel detected, "
                           "implementation is VULNERABLE.")
        elif skillings_mack_pvalue < 1e-9:
            explanation = ("Definite side-channel detected, "
                           "implementation is VULNERABLE.")
        elif skillings_mack_pvalue < 1e-5:
            explanation = ("Results suggesting side-channel found, "
                           "collecting more data necessary for confirmation.")
        else:
            k_sizes = list(self._bit_size_bootstraping.keys())
            k_sizes.sort(reverse=True)
            top_k_sizes = k_sizes[1:5]

            if len(top_k_sizes) == 0:
                explanation = "Not enough bit sizes detected."
                difference = 2
                return difference, explanation

            # We want the larger_ci to be the larger one in top bit sizes in
            # a method but the smallest one between methods. If one of the
            # tested methods shows that we have small enough CIs, we can use
            # use this one.
            larger_ci = min(
                max(
                    self._bit_size_bootstraping[k_size][method][1]
                    for k_size in top_k_sizes
                ) for method in self._bit_size_bootstraping[top_k_sizes[0]]
            )

            if larger_ci < 1e-10:
                explanation = ("Implementation verified as not "
                               "providing a timing side-channel signal.")
                difference = 0
            elif larger_ci < 1e-9:
                explanation = ("Implementation most likely not "
                               "providing a timing side-channel signal.")
                difference = 0
            elif larger_ci < 1e-2:
                explanation = ("Large confidence intervals detected, "
                               "collecting more data necessary. Side channel "
                               "leakage smaller than {0:.2e}s is possible."
                               .format(larger_ci))
            else:
                explanation = ("Very large confidence intervals detected. "
                               "Incorrect or missing --clock-frequency "
                               "option?")

        return difference, explanation

    def _bit_size_write_summary(self, verdict, skillings_mack_pvalue):
        """Wrights summary to the report.txt"""
        all_sign_test_values = list(self._bit_size_sign_test.values())
        all_wilcoxon_values = list(self._bit_size_wilcoxon_test.values())
        total_non_max_data = sum(self._k_sizes[i] for i in self._k_sizes
                                 if i != max(self._k_sizes.keys()))
        total_non_max_data += self._sanity_data_points_used
        with open(join(self.output, "analysis_results/report.txt"), "w") as fp:
            fp.write(
                "tlsfuzzer analyse.py version {0} bit size analysis\n\n"
                    .format(VERSION) +
                "Skilling-Mack test p-value: {0:.6e}\n"
                    .format(skillings_mack_pvalue) +
                "Sign test p-values (min, average, max): " +
                "{0:.2e}, {1:.2e}, {2:.2e}\n"
                    .format(
                        min(all_sign_test_values),
                        np.average(all_sign_test_values),
                        max(all_sign_test_values),
                    ) +
                "Wilcoxon test p-values (min, average, max): " +
                "{0:.2e}, {1:.2e}, {2:.2e}\n"
                    .format(
                        min(all_wilcoxon_values),
                        np.average(all_wilcoxon_values),
                        max(all_wilcoxon_values),
                    ) +
                "Used {0:,} ({2:.2%}) out of {1:,} available data "
                    .format(
                        self._total_bit_size_data_used,
                        total_non_max_data,
                        self._total_bit_size_data_used / total_non_max_data
                    ) +
                "observations for results.\n" +
                verdict + "\n\n" + ("-" * 88) + "\n" +
                "| size | Sign test | Wilcoxon test " +
                "|    {0}    |    {1}   |\n"
                    .format(
                        self._bit_size_methods["trim_mean_05"],
                        self._bit_size_methods["trim_mean_45"]
                    )
            )

            for k_size in self._bit_size_bootstraping:
                bootstraping_of_size = self._bit_size_bootstraping[k_size]

                if bootstraping_of_size["trim_mean_05"][0] < 0:
                    trim_mean_05 = "{0:.3e} (±{1:.2e}s)".format(
                        bootstraping_of_size["trim_mean_05"][0],
                        bootstraping_of_size["trim_mean_05"][1]
                    )
                else:
                    trim_mean_05 = " {0:.3e} (±{1:.2e}s)".format(
                        bootstraping_of_size["trim_mean_05"][0],
                        bootstraping_of_size["trim_mean_05"][1]
                    )

                if bootstraping_of_size["trim_mean_45"][0] < 0:
                    trim_mean_45 = "{0:.3e} (±{1:.2e}s)".format(
                        bootstraping_of_size["trim_mean_45"][0],
                        bootstraping_of_size["trim_mean_45"][1]
                    )
                else:
                    trim_mean_45 = " {0:.3e} (±{1:.2e}s)".format(
                        bootstraping_of_size["trim_mean_45"][0],
                        bootstraping_of_size["trim_mean_45"][1]
                    )

                fp.write(
                    ("|  {0} |  {1:.2e} |    {2:.2e}   | {3} | {4} |\n")
                    .format(
                        k_size, self._bit_size_sign_test[k_size],
                        self._bit_size_wilcoxon_test[k_size],
                        trim_mean_05, trim_mean_45
                    )
                )

            fp.write(("-" * 88) + "\n")

    def _k_sizes_totals_worker(self, args):
        name_bin, bounds = args
        start, end = bounds
        k_size_totals = defaultdict(int)

        data = np.memmap(name_bin,
                         dtype=[('tuple_num', np.dtype('i8')),
                                ('k_size', np.dtype('i2')),
                                ('value', np.dtype('f8'))],
                         mode="r")

        k_sizes = data['k_size']

        for k_size in k_sizes[start:end]:
            k_size_totals[k_size] += 1

        return k_size_totals

    def _k_sizes_totals(self, name_bin):
        k_sizes_totals = defaultdict(int)
        total_data = os.path.getsize(name_bin) // 18
        chunk_size = min(1024*1024,
                         max(10, total_data // (os.cpu_count() * 100)))

        if self.verbose:
            print('[i] Starting k-sizes counting')

        with mp.Pool(self.workers) as pool:
            # while it's accessing a protected member of a python class,
            # it's a). been there for a long time (at least 2.7) and
            # b). it's because of a bug in multiprocessing module itself:
            # https://github.com/python/cpython/issues/96062
            # pylint: disable=protected-access
            workers = set(pool._pool)

            chunks = pool.imap_unordered(
                # slice the data so that every worker has at least good few
                # dozen megabytes of data to work with
                self._k_sizes_totals_worker,
                ((name_bin, i) for i in _slices(total_data, chunk_size))
            )

            k_sizes_totals = defaultdict(int)
            for subtotals in chunks:
                for key in subtotals:
                    k_sizes_totals[key] += subtotals[key]

                workers.update(pool._pool)
                self._check_if_workers_are_alive(workers)
            # pylint: enable=protected-access

        k_sizes_totals = dict(sorted(k_sizes_totals.items(), reverse=True))
        self._k_sizes = k_sizes_totals

        if self.verbose:
            print("[i] Max K size detected: {0}"
                  .format(max(k_sizes_totals.keys())))
            print("[i] Min K size detected: {0}"
                  .format(min(k_sizes_totals.keys())))

    def generate_report(self, bit_size=False, hamming_weight=False):
        """
        Compiles a report consisting of statistical tests and plots.

        :return: int 0 if no difference was detected, 1 otherwise
        """
        if hamming_weight:
            difference = self.analyse_hamming_weights()
            with open(join(
                self.output, "analysis_results/report.Hamming_weight.txt"
            ), "w") as fp:
                fp.write(self._hamming_weight_report)
        elif bit_size:
            name = join(self.output, self.measurements_filename)
            name_bin = self._remove_suffix(name, '.csv') + '.bin'
            self._long_format_to_binary(name, name_bin)
            self._k_sizes_totals(name_bin)

            skillings_mack_pvalue = self.skillings_mack_test(name_bin)
            ret_val = self.analyze_bit_sizes()
            difference, verdict = self._bit_size_come_to_verdict(
                ret_val, skillings_mack_pvalue
            )
            self._bit_size_write_summary(verdict, skillings_mack_pvalue)
        else:
            # the Friedman test is fairly long running, non-multithreadable
            # and with fairly limited memory use, so run it in background
            # unconditionally
            friedman_result = mp.Queue()
            friedman_process = mp.Process(target=self.friedman_test,
                                          args=(friedman_result, ))
            friedman_process.start()
            # plot in separate processes so that the matplotlib memory leaks
            # are not cumulative, see
            # https://stackoverflow.com/q/28516828/462370
            processes = []
            processes.append(
                self._start_thread(self.box_plot,
                                   "Box plot graph generation failed"))
            processes.append(
                self._start_thread(self.scatter_plot,
                                   "Scatter plot graph generation failed"))
            processes.append(
                self._start_thread(self.ecdf_plot,
                                   "ECDF graph generation failed"))
            processes.append(
                self._start_thread(self.conf_interval_plot,
                                   "Conf interval graph generation failed"))
            processes.append(
                self._start_thread(self.diff_ecdf_plot,
                                   "Generation of ECDF graph of differences "
                                   "failed"))
            processes.append(
                self._start_thread(self.diff_scatter_plot,
                                   "Generation of scatter plot of differences "
                                   "failed"))

            self._write_legend()

            processes.append(
                self._start_thread(self._write_sample_stats,
                                   "Generation of sample statistics failed"))

            difference, p_vals, sign_p_vals, worst_pair = \
                self._write_individual_results()

            worst_pair_conf_int = self.calc_diff_conf_int(worst_pair)

            self.graph_worst_pair(worst_pair)

            friedman_process.join()

            difference = self._write_summary(difference, p_vals, sign_p_vals,
                                             worst_pair,
                                             friedman_result.get(),
                                             worst_pair_conf_int)

            friedman_result.close()
            friedman_result.join_thread()
            self._stop_all_threads(processes)

        return difference

    def _read_bit_size_measurement_file(self, status=None):
        """Returns an iterator with the data from the measurements file."""
        with open(join(self.output, self.measurements_filename), 'r') as in_fp:
            if status:
                in_fp.seek(0, 2)
                status[1] = in_fp.tell()
                in_fp.seek(0)

            first_line = in_fp.readline().split(',')
            previous_row = int(first_line[0])
            max_k_size = int(first_line[1])
            previous_max_k_value = float(first_line[2])

            if self.clock_frequency:
                previous_max_k_value /= self.clock_frequency

            chunks = pd.read_csv(
                in_fp, iterator=True, chunksize=100000,
                dtype=[("row", np.uint64), ("k_size", np.uint16),
                       ("value", np.float64)],
                names=["row", "k_size", "value"])

            for chunk in chunks:
                if self.clock_frequency:
                    chunk["value"] /= self.clock_frequency

                if status:
                    status[0] = in_fp.tell()

                rows, k_sizes, values = \
                    chunk["row"], chunk["k_size"], chunk["value"]

                # Row switching always happens on k_size == max_k_size

                # input:
                #     rows            0 0 1 1 2 2 2 3 3 3
                #     k_sizes         9 8 9 8 9 8 9 9 9 7
                #     values          a b c d e f g h i j
                # intermediates:
                #     row_same          T   T   T T   T T
                #     curr_maxk_vals' a - c - e - - h - -
                #     curr_maxk_vals' a a c c e e e h h h
                #     mask            F   F   F   F F F   (skip_sanity=True)
                #     mask                F   F   F F     (skip_sanity=False)
                # output:
                #     curr_maxk_vals  a a   c   e     h h
                #     values          a b   d   f     i j
                #     k_sizes         9 8   8   8     9 7

                row_same = rows.eq(rows.shift(fill_value=previous_row))

                curr_maxk_vals = values.mask(row_same)
                if rows.iat[0] == previous_row:
                    curr_maxk_vals.iat[0] = previous_max_k_value
                curr_maxk_vals = curr_maxk_vals.ffill()

                mask = row_same
                if self.skip_sanity:
                    mask &= k_sizes.ne(max_k_size)

                out = chunk.drop(columns="row")
                out = out.assign(curr_maxk_val=curr_maxk_vals)[mask]
                yield max_k_size, out

                previous_row = rows.iat[-1]
                previous_max_k_value = curr_maxk_vals.iat[-1]

    def _k_specific_writing_worker(self, args):
        k_folder_path, pipe, k_size, max_k_size, acceptance_percent = args
        items_written = 0

        os.makedirs(k_folder_path)

        try:
            with open(join(k_folder_path, "timing.csv"), 'w') as f:
                if k_size != max_k_size:
                    header = "{0},{1}\n".format(max_k_size, k_size)
                else:
                    header = "{0},{0}-sanity\n".format(max_k_size)
                f.write(header)

                while True:
                    subchunk = pipe.recv()
                    if subchunk is None:
                        break
                    subchunk = subchunk[['curr_maxk_val', 'value']]
                    for item in subchunk.values:
                        if random.random() <= acceptance_percent:
                            f.write("{0},{1}\n".format(*item))
                            items_written += 1
        finally:
            pipe.close()

        return (k_size, items_written)

    def create_k_specific_dirs(self):
        """
        Creates a folder with timing.csv for each K bit-size so it can be
        analyzed one at a time.
        """
        k_size_process_pipes = {}
        k_folder_paths = {}
        acceptance_percentages = {}
        max_k_size = max(self._k_sizes.keys())

        if self.verbose:
            print("Creating a dir for each bit size...")

        status = None
        if self.verbose:
            try:
                status = [0, 0, Event()]
                kwargs = {}
                kwargs['unit'] = ' bytes'
                kwargs['delay'] = self.delay
                kwargs['end'] = self.carriage_return
                progress = Thread(target=progress_report, args=(status,),
                                  kwargs=kwargs)
                progress.start()
            except FileNotFoundError:  # pragma: no cover
                pass

        measurement_iter = self._read_bit_size_measurement_file(status=status)

        for k_size in self._k_sizes:
            k_size_process_pipes[k_size] = mp.Pipe(duplex=False)
            k_folder_paths[k_size] = join(
                self.output, "analysis_results/k-by-size/{0}".format(k_size))
            acceptance_percentages[k_size] = 1
            if self._bit_size_data_limit:
                acceptance_percentages[k_size] = (
                    self._bit_size_data_limit / self._k_sizes[k_size])

        with mp.Pool(len(self._k_sizes)) as p:
            chunks = p.imap_unordered(
                self._k_specific_writing_worker,
                ((k_folder_paths[k_size], k_size_process_pipes[k_size][0],
                  k_size, max_k_size, acceptance_percentages[k_size])
                 for k_size in self._k_sizes.keys())
            )

            try:
                for max_k_size, chunk in measurement_iter:
                    for k_size, subchunk in chunk.groupby("k_size"):
                        _, pipe = k_size_process_pipes[k_size]
                        pipe.send(subchunk)
            finally:
                for _, pipe in k_size_process_pipes.values():
                    pipe.send(None)
                    pipe.close()

                tuples_written_in_timing_files = {}
                for k_size, total in chunks:
                    tuples_written_in_timing_files[k_size] = total

                    if k_size == max_k_size:
                        self._sanity_data_points_used = total

                if status:
                    status[2].set()
                    progress.join()
                    print()

        return tuples_written_in_timing_files

    def conf_plot_for_all_k(self):
        """
        Creates a confidence interval plot that includes all the K bit-sizes
        analysed.
        """
        boots = {
            "mean": {},
            "median": {},
            "trim_mean_05": {},
            "trim_mean_25": {},
            "trim_mean_45": {},
            "trimean": {}
        }

        for k_size in self._k_sizes:
            k_size_path = join(
                self.output, "analysis_results/k-by-size/{0}".format(k_size)
            )
            for method in list(boots.keys()):
                with open(
                    join(
                        k_size_path, "bootstrapped_{0}.csv".format(method)
                    ), 'r', encoding='utf-8'
                ) as fp:
                    boots[method][k_size] = [
                        float(x) for x in fp.read().splitlines()[1:]
                    ]

        for name in boots:
            number_of_k_sizes = len(boots[name].keys())

            name_readable = name
            if name == "trim_mean_05":
                name_readable = "trim mean (5%)"
            elif name == "trim_mean_25":
                name_readable = "trim mean (25%)"
            elif name == "trim_mean_45":
                name_readable = "trim mean (45%)"

            for start in range(0, number_of_k_sizes, 10):
                end = min(start + 10, number_of_k_sizes)
                fig = Figure(figsize=((end - start) * 2, 10))
                canvas = FigureCanvas(fig)

                ax = fig.add_subplot(1, 1, 1)
                ax.violinplot(
                    list(boots[name].values())[start:end], range(end - start),
                    widths=0.7, showmeans=True, showextrema=True
                )

                ax.set_xticks(range(end - start))
                ax.set_xticklabels(list(boots[name].keys())[start:end])

                formatter = mpl.ticker.EngFormatter('s')
                ax.get_yaxis().set_major_formatter(formatter)

                ax.set_title(
                    "Confidence intervals for {0} of differences".format(name)
                )
                ax.set_xlabel("K bit size")
                ax.set_ylabel("{0} of differences".format(name_readable))

                canvas.print_figure(
                    join(
                        self.output, "analysis_results",
                        "conf_interval_plot_all_k_sizes_{0}_{1}-{2}.png"
                            .format(name, start, end)
                    ), bbox_inches="tight"
                )

    def _check_data_for_zero(self):
        non_zero_diffs = 0
        ret_val = False

        with open(join(self.output, "timing.csv"), 'r') as fp:
            chunks = pd.read_csv(
                fp, iterator=True, chunksize=10, skiprows=1,
                dtype=[("max_k", np.float32), ("non_max_k", np.float32)],
                names=["max_k", "non_max_k"]
            )
            for chunk in chunks:
                for diff in chunk["max_k"] - chunk["non_max_k"]:
                    if diff != 0:
                        non_zero_diffs += 1
                if non_zero_diffs >= 3:
                    ret_val = True
                    break

        return ret_val

    def _bit_size_smart_analysis_worker(self, args):
        name_bin, bounds = args
        start, end = bounds
        max_k_size_value = -1
        prev_tupple_id = -1
        tuple_id = 0
        i = start
        chosen_tuples = []
        max_k_size = max(self._k_sizes.keys())
        total_second_k_size = self._k_sizes[max_k_size - 1]
        acceptance_percent = self._bit_size_data_limit / total_second_k_size

        data = np.memmap(name_bin,
                         dtype=[('tuple_num', np.dtype('i8')),
                                ('k_size', np.dtype('i2')),
                                ('value', np.dtype('f8'))],
                         mode="r")

        tuple_ids = data['tuple_num']
        k_sizes = data['k_size']
        values = data['value']

        k_sizes_len = len(k_sizes)
        while i < k_sizes_len and k_sizes[i] != max_k_size:
            i += 1

        while i < end or prev_tupple_id == tuple_id:
            random_number = random.random()
            prev_tupple_id = tuple_id
            try:
                tuple_id = tuple_ids[i]
                k_size = k_sizes[i]
                value = values[i]
            except IndexError:
                break

            if k_size == max_k_size:
                max_k_size_value = value

            if k_size == max_k_size - 1:
                if random_number <= acceptance_percent:
                    chosen_tuples.append((max_k_size_value, value))

            i += 1

        return end - start, chosen_tuples

    def _figure_out_analysis_data_size(self):
        pair = TestPair(0, 1)
        old_vebose = self.verbose
        self.verbose = False
        max_limit = 0
        total_data = sum(self._k_sizes[i] for i in self._k_sizes)
        name_bin = join(self.output,
                        self._remove_suffix(
                            self.measurements_filename, '.csv'
                        ) + '.bin')
        old_output = self.output
        self.output = join(old_output, "analysis_results/recon_data")
        chunk_size = min(1024*1024,
                         max(10, total_data // (os.cpu_count() * 100)))

        status = None
        if old_vebose:
            print('[i] Starting calculating needed amount of data')
            try:
                status = [0, total_data, Event()]
                kwargs = {}
                kwargs['unit'] = ' obs'
                kwargs['delay'] = self.delay
                kwargs['end'] = self.carriage_return
                progress = Thread(target=progress_report, args=(status,),
                                  kwargs=kwargs)
                progress.start()
            except FileNotFoundError:  # pragma: no cover
                pass

        os.makedirs(self.output, exist_ok=True)

        try:
            with mp.Pool(self.workers) as pool:
                # while it's accessing a protected member of a python class,
                # it's a). been there for a long time (at least 2.7) and
                # b). it's because of a bug in multiprocessing module itself:
                # https://github.com/python/cpython/issues/96062
                # pylint: disable=protected-access
                workers = set(pool._pool)

                chunks = pool.imap_unordered(
                    self._bit_size_smart_analysis_worker,
                    ((name_bin, i) for i in _slices(total_data, chunk_size))
                )

                chosen_tuples = []
                for subprocess_progress, subprocess_tuples in chunks:
                    chosen_tuples.extend(subprocess_tuples)

                    if status:
                        status[0] += subprocess_progress

                    workers.update(pool._pool)
                    self._check_if_workers_are_alive(workers)
                # pylint: enable=protected-access
        finally:
            if status:
                status[2].set()
                progress.join()
                print()

        with open(join(self.output, "timing.csv"), 'w') as fp:
            fp.write('max,max-1\n')

            for item in chosen_tuples:
                fp.write("{0},{1}\n".format(item[0], item[1]))

        recognition_results = self.calc_diff_conf_int(pair)
        recognition_cis = [
            recognition_results[method][2] - recognition_results[method][0]
            for method in recognition_results
        ]
        non_zero_recognition_cis = [x for x in recognition_cis if x > 0]

        if len(non_zero_recognition_cis) == 0:
            print("[W] There is not enough data on recognition size to " +
                  "calculate desired sample size. " +
                  "Using all available samples.")
            self._bit_size_data_limit = None
            self._bit_size_data_used = None
            self.verbose = old_vebose
            self.output = old_output
            return

        smaller_recognition_ci = min(
            x for x in non_zero_recognition_cis if x > 0)
        magnitude_diff = smaller_recognition_ci / self.bit_size_desired_ci
        max_limit = max(max_limit, round(
            (magnitude_diff ** 2) * self._bit_size_data_used))
        self._bit_size_data_used = None

        # We add 10% to the data limit to make sure that we have a smaller CI
        # (aim for CI 5% smaller than requested)
        self._bit_size_data_limit = round(max_limit * 1.1)
        self.verbose = old_vebose
        self.output = old_output

        if self.verbose:
            print(
                "[i] Calculated that {0:,} samples are needed for {1:.3}s CI."
                    .format(
                        self._bit_size_data_limit, self.bit_size_desired_ci)
            )

    def analyze_bit_sizes(self):
        """
        Analyses K bit-sizes and creates the plots and the test result files
        which are placed in an analysis_results directory in the output folder.

        Tests: Sign test, paired t-test and wilcoxon test.
        Graphs: Conf interval plot, diff ecdf plot and diff scatter plot.
        """
        out_dir = join(self.output, "analysis_results")
        testPair = (0, 1)
        original_output = self.output
        tests_to_perfom = [
            "sign_test", "paired_t_test", "wilcoxon_test", "bootstrap_test"
        ]
        ret_val = 0
        total_non_max_data = sum(self._k_sizes[i] for i in self._k_sizes
                                 if i != max(self._k_sizes.keys()))

        output_files = {}

        if self.verbose:
            print('[i] Starting bit size analysis')

        if os.path.exists(join(self.output, "analysis_results")):
            shutil.rmtree(join(self.output, "analysis_results"))

        if (
            self._bit_size_data_limit and
            total_non_max_data > self._bit_size_data_limit
        ):
            self._figure_out_analysis_data_size()

        samples_in_timing_files = self.create_k_specific_dirs()
        alpha_with_correction = (self.alpha / len(self._k_sizes))
        max_k_size = max(self._k_sizes.keys())

        for test in tests_to_perfom:
            output_files[test] = open(
                join(out_dir, "{0}.results".format(test)),
                'w', encoding="utf-8"
            )

        for k_size in self._k_sizes:
            if self.verbose:
                print('Running test for k size {0}...'.format(k_size))

            self.output = join(out_dir, "k-by-size/{0}".format(k_size))
            data = self.load_data()
            self.class_names = list(data)
            samples = samples_in_timing_files[k_size]

            # Sign test
            total = 0
            passed = 0

            with open(join(self.output, "timing.csv")) as in_fp:
                in_csv = csv.reader(in_fp)
                next(in_csv)
                for row in in_csv:
                    if row[0] != row[1]:
                        if float(row[1]) > float(row[0]):
                            passed += 1
                        total += 1

            if total > 10:
                pvalue = None
                try:
                    results = stats.binomtest(
                        passed, total, p=0.5, alternative="two-sided"
                    )
                    pvalue = results.pvalue
                except AttributeError:
                    pvalue = stats.binom_test(
                        passed, total, p=0.5, alternative="two-sided"
                    )

                output_files['sign_test'].write(
                    "K size of {0}: {1} ({2} out of {3} passed)\n"\
                        .format(k_size, pvalue, passed, total)
                )
                self._bit_size_sign_test[k_size] = pvalue

                if pvalue < alpha_with_correction:
                    ret_val = 1
            else:
                output_files['sign_test'].write(
                    "K size of {0}: Too few points\n".format(k_size)
                )

            # Paired t-test
            if self._check_data_for_zero():
                results = self.rel_t_test()
                output_files['paired_t_test'].write(
                    "K size of {0}: {1}\n".format(k_size, results[(0, 1)])
                )

                results = self.wilcoxon_test()
                pvalue = results[(0, 1)]
                output_files['wilcoxon_test'].write(
                    "K size of {0}: {1}\n".format(k_size, pvalue)
                )
                self._bit_size_wilcoxon_test[k_size] = pvalue
                if pvalue < alpha_with_correction:
                    ret_val = 1
            else:
                if self.verbose:
                    print("[i] Not enough data to perform reliable "
                          "paired t-test.")
                    print("[i] Not enough data to perform reliable "
                          "Wilcoxon signed-rank test.")

                output_files['paired_t_test'].write(
                    "K size of {0}: Too few points\n".format(k_size)
                )
                output_files['wilcoxon_test'].write(
                    "K size of {0}: Too few points\n".format(k_size)
                )

            # Creating graphs
            self.conf_interval_plot()
            self.diff_ecdf_plot()
            self.diff_scatter_plot()
            try:
                self.graph_worst_pair(testPair)
            except AssertionError:  # pragma: no cover
                if self.verbose:
                    print(
                        "[i] Couldn't create worst pair graph.".format(
                            k_size
                        )
                    )

            # Bootstrap test
            if k_size == max_k_size:
                output_files['bootstrap_test'].write(
                    "For K size {0} (sanity) ({1} samples):\n".format(
                        max_k_size,
                        samples
                    )
                )
            else:
                output_files['bootstrap_test'].write(
                    "For K size {0} ({1} samples):\n".format(
                        k_size,
                        samples
                    )
                )

            data = self.load_data()
            diff = data.iloc[:, 1] - data.iloc[:, 0]
            exact_values = self._calc_exact_values(diff)

            if samples > 50:
                if self.verbose:
                    print("[i] Reusing bootstraps to calculate 95% CI")

                bootstraping_results = {}
                for method, human_readable in self._bit_size_methods.items():
                    results = []
                    with open(join(
                            self.output, "bootstrapped_{0}.csv".format(method)
                            )) as fp:
                        results = fp.readlines()[1:]

                    results = list(map(lambda x: float(x), results))
                    calc_quant = np.quantile(results, [0.025, 0.975])

                    output_files['bootstrap_test'].write(
                        "{0} of differences: ".format(human_readable) +
                        "{0}s, 95% CI: {1}s, {2}s (±{3}s)\n"
                            .format(
                                exact_values[method], calc_quant[0],
                                calc_quant[1], (calc_quant[1] - calc_quant[0])
                            )
                    )
                    if method in ["trim_mean_05", "trim_mean_45"]:
                        bootstraping_results[method] = (
                            exact_values[method], calc_quant[1] - calc_quant[0]
                        )
                if len(self._bit_size_bootstraping) < 10:
                    self._bit_size_bootstraping[k_size] = bootstraping_results

                output_files['bootstrap_test'].write("\n")
            else:
                if self.verbose:
                    print("[i] Not enough data to perform reliable "
                          "bootstraping ({0} observations)".format(samples))

                for method, human_readable in self._bit_size_methods.items():
                    output_files['bootstrap_test'].write(
                        "{0} of differences: {1}s\n".format(
                            human_readable, exact_values[method]
                        )
                    )
                output_files['bootstrap_test'].write("\n")

            if self._bit_size_data_used:
                self._total_bit_size_data_used += self._bit_size_data_used
                self._bit_size_data_used = None

        for key in output_files:
            output_files[key].close()

        self.output = original_output
        self.class_names = []

        if self.verbose:
            print("[i] Create conf value plot for all K sizes")
            start_time = time.time()
        self.conf_plot_for_all_k()
        if self.verbose:
            print("[i] Plot for all K sizes created in {:.3}s".format(
                time.time()-start_time))

        return ret_val

    def _read_hamming_weight_data(self, name, mode="r"):
        # first make sure the binary file exists
        data = np.memmap(name,
                         dtype=[('block', np.dtype('i8')),
                                ('group', np.dtype('i2')),
                                ('value', np.dtype('f8'))],
                         mode=mode)
        return data

    def _read_tuples(self, data):
        current_block_id = None
        block_values = dict()
        for value, group, block in zip(data['value'],
                                       data['group'],
                                       data['block']):
            if block != current_block_id:
                if block_values:
                    yield block_values
                    block_values = dict()
                current_block_id = block
            block_values[group] = value
        if block_values:
            yield block_values

    def _add_value_to_group(self, name, group, diff):
        data = self._read_hamming_weight_data(name, mode="r+")
        try:
            groups = data['group']
            values = data['value']
            values[groups == group] += diff
        finally:
            del data

    def _split_data_to_pairwise(self, name):
        data = self._read_hamming_weight_data(name)
        try:
            pair_writers = dict()

            unique_vals, unique_counts = np.unique(data['group'],
                                                   return_counts=True)
            group_counts = list((i, j)
                                for i, j
                                in zip(unique_vals, unique_counts))
            group_counts = sorted(group_counts,
                                  key=lambda x: x[1])
            most_common = set(i for i, j in group_counts[-5:])

            slope_path = join(self.output,
                              "analysis_results/by-pair-sizes/slope")
            os.makedirs(slope_path, exist_ok=True)

            pair_writers['slope'] = open(
                    join(slope_path, "timing.csv"), "w")
            pair_writers['slope'].write(
                    "lower,higher\n")

            for block_vals in self._read_tuples(data):
                # save data to estimate the slope of the time to Hamming weight
                # dependency (if there is no dependency then the slope will
                # be 0
                i = iter(sorted(block_vals.items()))
                for lower, higher in zip(i, i):
                    pair_writers['slope'].write(
                        "{0},{1}\n".format(lower[1], higher[1]))

                # create pairwise comparisons graphs only for the most common
                # groups, skip blocks that have only uncommon groups in them
                for base_group in most_common.intersection(block_vals.keys()):
                    base_value = block_vals[base_group]
                    for compared_group, compared_value in block_vals.items():
                        if base_group == compared_group:
                            continue

                        pair = (base_group, compared_group)
                        # if it's a new pair, open the file for it and write
                        # a header
                        if pair not in pair_writers:
                            pair_path = join(
                                    self.output,
                                    "analysis_results/by-pair-sizes/"
                                    "{0:04d}-{1:04d}"
                                    .format(base_group, compared_group))
                            try:
                                os.makedirs(pair_path)
                            except FileExistsError:
                                pass
                            pair_writers[pair] = open(
                                    join(pair_path, "timing.csv"), "w")
                            pair_writers[pair].write(
                                    "{0},{1}\n".format(base_group,
                                                       compared_group))

                        pair_writers[pair].write(
                                "{0},{1}\n".format(base_value, compared_value))

        finally:
            del data
            for writer in pair_writers.values():
                writer.close()

        return [i for i, j in group_counts[-5:]], pair_writers.keys()

    def _analyse_weight_pairs(self, pairs):
        out_dir = self.output
        output_files = dict()
        if self.run_sign_test:
            output_files['sign_test'] = open(
                join(out_dir, "analysis_results", "sign_test.results"),
                "w", encoding="utf-8")
        if self.run_t_test:
            output_files['t_test'] = open(
                join(out_dir, "analysis_results", "t_test.results"),
                "w", encoding="utf-8")
        if self.run_wilcoxon_test:
            output_files['wilcoxon_test'] = open(
                join(out_dir, "analysis_results", "wilcoxon_test.results"),
                "w", encoding="utf-8")
        try:
            if any((self.run_sign_test, self.run_wilcoxon_test,
                    self.run_t_test, self.draw_conf_interval_plot,
                    self.draw_ecdf_plot)):
                for base_group, test_group in \
                        sorted(i for i in pairs if i != 'slope'):
                    if self.verbose:
                        print("Running test for {0}-{1}..."
                              .format(base_group, test_group))

                    self.output = join(
                        out_dir,
                        "analysis_results/by-pair-sizes/"
                        "{0:04d}-{1:04d}"
                            .format(base_group, test_group))

                    data = self.load_data()
                    self.class_names = list(data)

                    if self.run_sign_test:
                        results = self.sign_test()
                        output_files['sign_test'].write(
                            "{0} to {1}: {2}\n".format(
                                base_group, test_group, results[(0, 1)]))

                    if self.run_wilcoxon_test:
                        results = self.wilcoxon_test()
                        output_files['wilcoxon_test'].write(
                            "{0} to {1}: {2}\n".format(
                                base_group, test_group, results[(0, 1)]))

                    if self.run_t_test:
                        results = self.rel_t_test()
                        output_files['t_test'].write(
                            "{0} to {1}: {2}\n".format(
                                base_group, test_group, results[(0, 1)]))

                    if self.draw_conf_interval_plot:
                        self.conf_interval_plot()
                    if self.draw_ecdf_plot:
                        self.diff_ecdf_plot()

            self.output = join(out_dir,
                               "analysis_results/by-pair-sizes/slope")
            data = self.load_data()
            self.class_names = list(data)

            self.run_sign_test = True
            sign_test_results = self.sign_test()
            sign_test_text = "Slope sign test: {0}".format(
                sign_test_results[(0, 1)])

            self.run_wilcoxon_test = True
            wilcoxon_test_results = self.wilcoxon_test()
            wilcoxon_test_text = "Slope Wilcoxon signed rank test: {0}"\
                .format(wilcoxon_test_results[(0, 1)])

            self.run_t_test = True
            rel_t_test_results = self.rel_t_test()
            rel_t_test_text = "Slope t-test: {0}".format(
                rel_t_test_results[(0, 1)])

            self._hamming_weight_report += '\n'
            self._hamming_weight_report += sign_test_text + '\n'
            self._hamming_weight_report += wilcoxon_test_text + '\n'
            self._hamming_weight_report += rel_t_test_text + '\n'
            if self.verbose:
                print("[i] " + sign_test_text)
                print("[i] " + wilcoxon_test_text)
                print("[i] " + rel_t_test_text)

            # conf_interval_plot is disabled by the draw_conf_interval_plot
            old_conf_interval = self.draw_conf_interval_plot
            self.draw_conf_interval_plot = True
            self.conf_interval_plot()
            self.draw_conf_interval_plot = old_conf_interval

        finally:
            self.output = out_dir
            for i in output_files.values():
                i.close()

        methods = {
            "mean": "Mean",
            "median": "Median",
            "trim_mean_05": "Trimmed mean (5%)",
            "trim_mean_25": "Trimmed mean (25%)",
            "trim_mean_45": "Trimmed mean (45%)",
            "trimean": "Trimean"
        }

        boots = dict()

        if self.draw_conf_interval_plot:
            for base_group, test_group in \
                    sorted(i for i in pairs if i != 'slope'):
                in_dir = join(out_dir,
                              "analysis_results/by-pair-sizes/{0:04d}-{1:04d}"
                              .format(base_group, test_group))

                if base_group not in boots:
                    boots[base_group] = dict(
                        (i, dict())
                        for i in methods
                    )

                for method in methods:
                    with open(join(in_dir,
                                   "bootstrapped_{0}.csv".format(method)),
                              "r", encoding='utf-8') as fp:
                        boots[base_group][method][
                                '{0}-{1}'.format(test_group, base_group)
                            ] = [
                            float(x) for x in fp if x != "1-0\n"
                        ]

            for base_group, data_by_method in boots.items():
                for method, values in data_by_method.items():
                    name_readable = methods[method]

                    min_max = len(values.keys())
                    # don't use smallest and biggest Hamming weights in the
                    # graph, they will have large confidence intervals anyway
                    start = int(min_max * 0.2)
                    stop = int(math.ceil(min_max * 0.8))

                    fig = Figure(figsize=(24, 12))
                    canvas = FigureCanvas(fig)
                    ax = fig.add_subplot(1, 1, 1)
                    ax.violinplot(list(values.values())[start:stop],
                                  widths=0.7,
                                  showmeans=True, showextrema=True)
                    ax.set_xticks(range(1, stop - start + 1, 4))
                    ax.set_xticklabels(list(values.keys())[start:stop:4])

                    formatter = mpl.ticker.EngFormatter('s')
                    ax.get_yaxis().set_major_formatter(formatter)

                    ax.set_title((
                        "Confidence intervals for {0} of differences with {1} "
                        "as baseline"
                        ).format(
                            name_readable, base_group
                        )
                    )
                    ax.set_xlabel("differences")
                    ax.set_ylabel("{0} of differences".format(name_readable))

                    canvas.print_figure(
                        join(
                            self.output,
                            "analysis_results",
                            "conf_interval_plot_{0}_{1}.png".format(
                                 base_group, method
                            )
                        ),
                        bbox_inches="tight"
                    )

        in_dir = join(out_dir,
                      "analysis_results/by-pair-sizes/slope")

        boots = dict()
        self._hamming_weight_report += ("\nBootstrapped confidence " +
                                        "intervals for the time/weight " +
                                        "slope\n")
        if self.verbose:
            print("[i] Bootstrapped confidence intervals " +
                  "for the time/weight slope")
        for method, method_name in methods.items():
            with open(join(in_dir, "bootstrapped_{0}.csv".format(method)),
                      "r", encoding='utf-8') as fp:
                boots[method] = [
                    float(x) for x in fp if x != "1-0\n"
                ]

            quantile = np.quantile(boots[method], [0.025, 0.975, 0.5])
            quantile_text = "{0} of differences: ".format(method_name)
            quantile_text += "{0:.5e} s/bit, 95% CI: {1:.5e} s/bit, ".format(
                quantile[2], quantile[0])
            quantile_text += "{0:.5e} s/bit (±{1:.3e} s/bit)".format(
                quantile[1], (quantile[1] - quantile[0])/2)

            self._hamming_weight_report += quantile_text + '\n'
            if self.verbose:
                print("[i] " + quantile_text)

    def analyse_hamming_weights(self):
        name = join(self.output, self.measurements_filename)

        self._hamming_weight_report += "tlsfuzzer analyse.py version {0} "\
            .format(VERSION)
        self._hamming_weight_report += "Hamming weight analysis "
        self._hamming_weight_report += "(experimental)\n\n"

        # first make sure the binary file exists
        name_bin = self._remove_suffix(name, '.csv') + ".bin"
        self._long_format_to_binary(name, name_bin)

        skillings_mack_p_value = self.skillings_mack_test(name_bin)

        self._hamming_weight_report += "Skillings-Mack test p-value: {0}\n"\
            .format(skillings_mack_p_value)

        most_common, pairs = self._split_data_to_pairwise(name_bin)

        sm_p_values = {}
        if skillings_mack_p_value > 1e-5:
            tmp_file = name_bin + ".tmp"
            self._hamming_weight_report += "Skillings-Mack test p-value after "
            self._hamming_weight_report += "introducing a side-channel of:\n"

            for time in [10, 1, 0.1]:
                shutil.copyfile(name_bin, tmp_file)
                self._add_value_to_group(tmp_file, most_common[0], time * 1e-9)
                p_value = self.skillings_mack_test(tmp_file)
                sm_p_values[time] = p_value
                self._hamming_weight_report += "\t{0}ns: {1}\n".format(
                    time, p_value)
                if self.verbose:
                    print("[i] {0}ns: {1}".format(time, p_value))
                os.remove(tmp_file)

        self._analyse_weight_pairs(pairs)

        if self.verbose:
            print("[i] Skillings-Mack test p-value: {0}".format(
                skillings_mack_p_value))
            if len(sm_p_values.keys()) is not None:
                for time in sm_p_values:
                    print(("[i] Sample large enough to detect {0} ns "
                           "difference: {1}").format(
                               time, sm_p_values[time] < 1e-9))

        if skillings_mack_p_value < self.alpha:
            return 1
        return 0


# exclude from coverage as it's a). trivial, and b). not easy to test
if __name__ == '__main__':  # pragma: no cover
    main_ret = main()
    print("Analysis return value: {}".format(main_ret))
    sys.exit(main_ret)
