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
from collections import namedtuple
from itertools import combinations, repeat, chain
import os
import time

import numpy as np
from scipy import stats
import pandas as pd
import matplotlib as mpl
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas

from tlsfuzzer.utils.ordered_dict import OrderedDict
from tlsfuzzer.utils.progress_report import progress_report
from tlsfuzzer.messages import div_ceil


TestPair = namedtuple('TestPair', 'index1  index2')
mpl.use('Agg')


VERSION = 6


_diffs = None
_DATA = None


def help_msg():
    """Print help message"""
    print("""Usage: analysis [-o output]
 -o output      Directory where to place results (required)
                and where timing.csv or measurements.csv is located
 --no-ecdf-plot Don't create the ecdf_plot.png file
 --no-scatter-plot Don't create the scatter_plot.png file
 --no-conf-interval-plot Don't create the conf_interval_plot.png file
 --multithreaded-graph Create graph and calculate statistical tests at the
                same time. Note: this increases memory usage of analysis by
                a factor of 8.
 --clock-frequency freq Assume that the times in the file are not specified in
                seconds but rather in clock cycles of a clock running at
                frequency 'freq' specified in MHz. Use when the clock source
                are the raw reads from the Time Stamp Counter register or
                similar.
 --alpha num    Acceptable probability of a false positive. Default: 1e-5.
 --verbose      Print the current task
 --workers num  Number of worker processes to use for paralelizable
                computation. More workers will finish analysis faster, but
                will require more memory to do so. By default: number of
                threads available on the system (`os.cpu_count()`).
 --status-delay num How often to print the status line for long-running tasks
                in seconds.
 --status-newline Use newline for printing status line, not carriage return,
                works better with output redirection to file.
 --bit-size     Specifies that the program will analyze bit-size measurement
                data from a measurements.csv file. A measurements.csv file
                is expected as input and it should be in long-format
                ("row id,column id,value").
 --skip-sanity  Skip sanity measurements from analysis (if any).
 --help         Display this message""")


def main():
    """Process arguments and start analysis."""
    output = None
    ecdf_plot = True
    scatter_plot = True
    conf_int_plot = True
    multithreaded_graph = False
    verbose = False
    clock_freq = None
    alpha = None
    workers = None
    delay = None
    carriage_return = None
    bit_size_analysis = False
    skip_sanity = False
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "o:",
                               ["help", "no-ecdf-plot", "no-scatter-plot",
                                "no-conf-interval-plot",
                                "multithreaded-graph",
                                "clock-frequency=",
                                "alpha=",
                                "workers=",
                                "status-delay=",
                                "status-newline",
                                "bit-size",
                                "skip-sanity",
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
        elif opt == "--status-delay":
            delay = float(arg)
        elif opt == "--status-newline":
            carriage_return = '\n'
        elif opt == "--bit-size":
            bit_size_analysis = True
        elif opt == "--skip-sanity":
            skip_sanity = True

    if output:
        analysis = Analysis(output, ecdf_plot, scatter_plot, conf_int_plot,
                            multithreaded_graph, verbose, clock_freq, alpha,
                            workers, delay, carriage_return, bit_size_analysis,
                            skip_sanity)
        if bit_size_analysis:
            ret = analysis.analyze_bit_sizes()
        else:
            ret = analysis.generate_report()

        return ret
    else:
        raise ValueError("Missing -o option!")


class Analysis(object):
    """Analyse extracted timing information from csv file."""

    def __init__(self, output, draw_ecdf_plot=True, draw_scatter_plot=True,
                 draw_conf_interval_plot=True, multithreaded_graph=False,
                 verbose=False, clock_frequency=None, alpha=None,
                 workers=None, delay=None, carriage_return=None,
                 bit_size_analysis=False, skip_sanity=False):
        self.verbose = verbose
        self.output = output
        self.clock_frequency = clock_frequency
        self.class_names = []
        self.draw_ecdf_plot = draw_ecdf_plot
        self.draw_scatter_plot = draw_scatter_plot
        self.draw_conf_interval_plot = draw_conf_interval_plot
        self.multithreaded_graph = multithreaded_graph
        self.workers = workers
        if alpha is None:
            self.alpha = 1e-5
        else:
            self.alpha = alpha
        self.delay = delay
        self.carriage_return = carriage_return
        self.skip_sanity = skip_sanity

        if not bit_size_analysis:
            data = self.load_data()
            self.class_names = list(data)

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
            pvals = list(pool.imap_unordered(
                self._mt_process_runner,
                zip(comb, repeat(sum_func), repeat(args)),
                job_size))
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
        sign_less_results = self.sign_test(alternative="less")
        sign_greater_results = self.sign_test(alternative="greater")
        ttest_results = self.rel_t_test()
        desc_stats = self.desc_stats()

        report_filename = join(self.output, "report.csv")
        p_vals = []
        sign_p_vals = []
        with open(report_filename, 'w') as file:
            writer = csv.writer(file)
            writer.writerow(["Class 1", "Class 2", "Box test",
                             "Wilcoxon signed-rank test",
                             "Sign test", "Sign test less",
                             "Sign test greater",
                             "paired t-test", "mean", "SD",
                             "median", "IQR", "MAD"])
            worst_pair = None
            worst_p = None
            worst_median_difference = None
            for pair, result in sorted(box_results.items()):
                index1, index2 = pair
                diff_stats = desc_stats[pair]
                box_write = "="
                if result:
                    print("Box test {0} vs {1}: {0} {2} {1}".format(index1,
                                                                    index2,
                                                                    result))
                    box_write = result
                else:
                    print("Box test {} vs {}: No difference".format(index1,
                                                                    index2))
                print("Wilcoxon signed-rank test {} vs {}: {:.3}"
                      .format(index1, index2, wilcox_results[pair]))
                print("Sign test {} vs {}: {:.3}"
                      .format(index1, index2, sign_results[pair]))
                print("Sign test, probability that {1} < {0}: {2:.3}"
                      .format(index1, index2, sign_less_results[pair]))
                print("Sign test, probability that {1} > {0}: {2:.3}"
                      .format(index1, index2, sign_greater_results[pair]))
                if sign_results[pair] > 0.05:
                    sign_test_relation = "="
                elif sign_less_results[pair] > sign_greater_results[pair]:
                    sign_test_relation = "<"
                else:
                    sign_test_relation = ">"
                print("Sign test interpretation: {} {} {}"
                      .format(index2, sign_test_relation, index1))
                print("Dependent t-test for paired samples {} vs {}: {:.3}"
                      .format(index1, index2, ttest_results[pair]))
                print("{} vs {} stats: mean: {:.3}, SD: {:.3}, median: {:.3}, "
                      "IQR: {:.3}, MAD: {:.3}".format(
                          index1, index2, diff_stats["mean"], diff_stats["SD"],
                          diff_stats["median"], diff_stats["IQR"],
                          diff_stats["MAD"]))

                # If either of the pairwise tests shows a small p-value with
                # Bonferroni correction consider it a possible side-channel
                if wilcox_results[pair] < self.alpha / len(sign_results) or \
                        sign_results[pair] < self.alpha / len(sign_results) or\
                        ttest_results[pair] < self.alpha / len(sign_results):
                    difference = 1

                wilcox_p = wilcox_results[pair]
                sign_p = sign_results[pair]
                ttest_p = ttest_results[pair]
                row = [self.class_names[index1],
                       self.class_names[index2],
                       box_write,
                       wilcox_p,
                       sign_p,
                       sign_less_results[pair],
                       sign_greater_results[pair],
                       ttest_p,
                       diff_stats["mean"],
                       diff_stats["SD"],
                       diff_stats["median"],
                       diff_stats["IQR"],
                       diff_stats["MAD"]
                       ]
                writer.writerow(row)

                p_vals.append(wilcox_p)
                sign_p_vals.append(sign_p)
                median_difference = abs(diff_stats["median"])

                if worst_pair is None or wilcox_p < worst_p or \
                        worst_median_difference is None or \
                        worst_median_difference < median_difference:
                    worst_pair = pair
                    worst_p = wilcox_p
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
            if friedman_p < self.alpha:
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
                    print("WARNING: all 95% CIs are equal 0. Too small sammple"
                          " or too low clock resolution for the measurement.")
                # when measuring values below clock frequency
                # or very small pieces of code with high resolution clock
                # it may cause the 95% CI to equal 0.0; that's not a realistic
                # value so ignore it
                # (for median it would be nice to actually check if we're not
                # in the vicinity of the clock resolution, and ignore median
                # then, but that's much more complex so don't do it for now)
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

    def generate_report(self):
        """
        Compiles a report consisting of statistical tests and plots.

        :return: int 0 if no difference was detected, 1 otherwise
        """
        # the Friedman test is fairly long running, non-multithreadable
        # and with fairly limited memory use, so run it in background
        # unconditionally
        friedman_result = mp.Queue()
        friedman_process = mp.Process(target=self.friedman_test,
                                      args=(friedman_result, ))
        friedman_process.start()
        # plot in separate processes so that the matplotlib memory leaks are
        # not cumulative, see https://stackoverflow.com/q/28516828/462370
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

        self._write_sample_stats()

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

    def _div_by_freq(self, data_iter):
        """Returns an iterator that data divided by given frequence."""
        for row in data_iter:
            row[2] = float(row[2]) / self.clock_frequency
            yield row

    def _read_bit_size_measurement_file(self):
        """Returns an iterator with the data from the measurements.csv file."""
        current_max_k_value = None
        max_k_size = None
        previous_row = None

        with open(join(self.output, "measurements.csv"), 'r') as in_fp:
            data_iter = csv.reader(in_fp)

            if self.clock_frequency:
                data_iter = self._div_by_freq(data_iter)

            row = next(data_iter)
            previous_row = row[0]
            max_k_size = row[1]
            current_max_k_value = row[2]

            yield (current_max_k_value, current_max_k_value, max_k_size)

            for row in data_iter:
                current_row = row[0]
                k_size = row[1]
                value = row[2]

                if k_size == max_k_size and previous_row != current_row:
                    current_max_k_value = value
                    previous_row = current_row
                    continue
                elif k_size == max_k_size and self.skip_sanity:
                    continue

                yield (current_max_k_value, value, k_size)

    def create_k_specific_dirs(self):
        """
        Creates a folder with timing.csv for each K bit-size so it can be
        analyzed one at a time.
        """
        k_sizes = []
        k_size_files = {}

        if self.verbose:
            print("Creating a dir for each K size...")

        data_iter = self._read_bit_size_measurement_file()

        data = next(data_iter)
        max_k_size = data[2]

        for data in data_iter:
            k_size = data[2]

            if k_size not in k_size_files:
                k_sizes.append(k_size)

                k_folder_path = join(
                    self.output,
                    "analysis_results/k-by-size/{0}".format(k_size)
                )
                os.makedirs(k_folder_path)
                k_size_files[k_size] = open(
                    join(k_folder_path, "timing.csv"), 'w',
                    encoding="utf-8"
                )
                if k_size != max_k_size:
                    k_size_files[k_size].write(
                        "{0},{1}\n".format(max_k_size, k_size)
                    )
                else:
                    k_size_files[k_size].write(
                        "{0},{1}-sanity\n".format(max_k_size, max_k_size)
                    )

            k_size_files[k_size].write("{0},{1}\n".format(data[0], data[1]))

        k_sizes = sorted(k_sizes, reverse=True)

        if self.skip_sanity and max_k_size in k_sizes:
            k_sizes.remove(max_k_size)

        if self.verbose:
            print("Max K size detected: {0}".format(max_k_size))
            print("Min K size detected: {0}".format(k_sizes[-1]))

        for k_size in k_size_files:
            k_size_files[k_size].close()

        if not self.skip_sanity:
            max_k_folder_path = join(
                self.output,
                "analysis_results/k-by-size/{0}".format(max_k_size)
            )
            with open(join(max_k_folder_path, "timing.csv"), 'r') as fp:
                for count, line in enumerate(fp):
                    pass
            if count < 2:
                shutil.rmtree(max_k_folder_path)
                k_sizes.remove(max_k_size)

        return k_sizes

    def conf_plot_for_all_k(self, k_sizes):
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

        for k_size in k_sizes:
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

        output_files = {}

        if os.path.exists(join(self.output, "analysis_results")):
            shutil.rmtree(join(self.output, "analysis_results"))

        k_sizes = self.create_k_specific_dirs()
        max_k_size = k_sizes[0]

        for test in tests_to_perfom:
            output_files[test] = open(
                join(out_dir, "{0}.results".format(test)),
                'w', encoding="utf-8"
            )

        for k_size in k_sizes:
            if self.verbose:
                print('Running test for k size {0}...'.format(k_size))

            self.output = join(out_dir, "k-by-size/{0}".format(k_size))
            data = self.load_data()
            self.class_names = list(data)
            samples = sum(
                1 for _ in open(join(
                    out_dir, "k-by-size/{0}/timing.csv".format(k_size)
                ), 'r')
            ) - 1

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

                if pvalue < (self.alpha / len(k_sizes)):
                    ret_val = 1
            else:
                output_files['sign_test'].write(
                    "K size of {0}: Too few points\n".format(k_size)
                )

            # Paired t-test
            results = self.rel_t_test()
            output_files['paired_t_test'].write(
                "K size of {0}: {1}\n".format(k_size, results[(0, 1)])
            )

            # Wilcoxon test
            results = self.wilcoxon_test()
            output_files['wilcoxon_test'].write(
                "K size of {0}: {1}\n".format(k_size, results[(0, 1)])
            )

            # Creating graphs
            self.conf_interval_plot()
            self.diff_ecdf_plot()
            self.diff_scatter_plot()
            try:
                self.graph_worst_pair(testPair)
            except AssertionError:
                if self.verbose:
                    print(
                        "[i] Couldn't create worst pair graph.".format(
                            k_size
                        )
                    )

            # Bootstrap test
            methods = {
                "mean": "Mean",
                "median": "Median",
                "trim_mean_05": "Trimmed mean (5%)",
                "trim_mean_25": "Trimmed mean (25%)",
                "trim_mean_45": "Trimmed mean (45%)",
                "trimean": "Trimean"
            }

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

                for method, human_readable in methods.items():
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
                output_files['bootstrap_test'].write("\n")
            else:
                if self.verbose:
                    print("[i] Not enough data to perform reliable "
                          "bootstraping ({0} observations)".format(samples))

                for method, human_readable in methods.items():
                    output_files['bootstrap_test'].write(
                        "{0} of differences: {1}s\n".format(
                            human_readable, exact_values[method]
                        )
                    )
                output_files['bootstrap_test'].write("\n")

        for key in output_files:
            output_files[key].close()

        self.output = original_output
        self.class_names = []

        if self.verbose:
            print("Create conf value plot for all K sizes...")
        self.conf_plot_for_all_k(k_sizes)

        return ret_val


# exclude from coverage as it's a). trivial, and b). not easy to test
if __name__ == '__main__':  # pragma: no cover
    main_ret = main()
    print("Analysis return value: {}".format(main_ret))
    sys.exit(main_ret)
