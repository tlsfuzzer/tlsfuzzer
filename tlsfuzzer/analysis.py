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
import multiprocessing as mp
import shutil
from itertools import chain
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

from tlsfuzzer.utils.ordered_dict import OrderedDict


TestPair = namedtuple('TestPair', 'index1  index2')
mpl.use('Agg')


VERSION = 5


_diffs = None
_DATA = None


def help_msg():
    """Print help message"""
    print("""Usage: analysis [-o output]
 -o output      Directory where to place results (required)
                and where timing.csv is located
 --no-ecdf-plot Don't create the ecdf_plot.png file
 --no-scatter-plot Don't create the scatter_plot.png file
 --no-conf-interval-plot Don't create the conf_interval_plot.png file
 --multithreaded-graph Create graph and calculate statistical tests at the
                same time. Note: this increases memory usage of analysis by
                a factor of 8.
 --help         Display this message""")


def main():
    """Process arguments and start analysis."""
    output = None
    ecdf_plot = True
    scatter_plot = True
    conf_int_plot = True
    multithreaded_graph = False
    argv = sys.argv[1:]
    opts, args = getopt.getopt(argv, "o:",
                               ["help", "no-ecdf-plot", "no-scatter-plot",
                                "no-conf-interval-plot",
                                "multithreaded-graph"])

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

    if output:
        analysis = Analysis(output, ecdf_plot, scatter_plot, conf_int_plot,
                            multithreaded_graph)
        ret = analysis.generate_report()
        return ret
    else:
        raise ValueError("Missing -o option!")


class Analysis(object):
    """Analyse extracted timing information from csv file."""

    def __init__(self, output, draw_ecdf_plot=True, draw_scatter_plot=True,
                 draw_conf_interval_plot=True, multithreaded_graph=False):
        self.output = output
        data = self.load_data()
        self.class_names = list(data)
        self.draw_ecdf_plot = draw_ecdf_plot
        self.draw_scatter_plot = draw_scatter_plot
        self.draw_conf_interval_plot = draw_conf_interval_plot
        self.multithreaded_graph = multithreaded_graph

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

        :param int interval1: index to data representing first sample
        :param int interval2: index to data representing second sample
        :param float quantile_start: starting quantile of the box
        :param float quantile_end: closing quantile of the box
        :return: None on no difference, int index of smaller sample if there
            is a difference
        """
        data = self.load_data()
        box1_start = np.quantile(data.iloc[:, interval1], quantile_start)
        box1_end = np.quantile(data.iloc[:, interval1], quantile_end)

        box2_start = np.quantile(data.iloc[:, interval2], quantile_start)
        box2_end = np.quantile(data.iloc[:, interval2], quantile_end)

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

    @staticmethod
    def _wilcox_test(data1, data2):
        return stats.wilcoxon(data1, data2)[1]

    def wilcoxon_test(self):
        """Cross-test all classes with the Wilcoxon signed-rank test"""
        return self.mt_process(self._wilcox_test)

    @staticmethod
    def _rel_t_test(data1, data2):
        """Calculate ttest statistic, return p-value."""
        return stats.ttest_rel(data1, data2)[1]

    def rel_t_test(self):
        """Cross-test all classes using the t-test for dependent, paired
        samples."""
        return self.mt_process(self._rel_t_test)

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
        with mp.Pool() as pool:
            pvals = list(pool.imap_unordered(
                self._mt_process_runner,
                zip(comb, repeat(sum_func), repeat(args)),
                job_size))
        results = dict(pvals)
        return results

    @staticmethod
    def _sign_test(data1, data2, med, alternative):
        diff = data2 - data1
        return stats.binom_test([sum(diff < med), sum(diff > med)], p=0.5,
                                alternative=alternative)

    def sign_test(self, med=0.0, alternative="two-sided"):
        """
        Cross-test all classes using the sign test.

        med: expected median value

        alternative: the alternative hypothesis, "two-sided" by default,
            can be "less" or "greater". If called with "less" and returned
            p-value is much smaller than 0.05, then it's likely that the
            *second* sample in a pair is bigger than the first one. IOW,
            with "less" it tells the probability that second sample is smaller
            than the first sample.
        """
        return self.mt_process(self._sign_test, (med, alternative))

    def friedman_test(self):
        """
        Test all classes using Friedman chi-square test.

        Note, as the scipy stats package uses a chisquare approximation, the
        test results are valid only when we have more than 10 samples.
        """
        data = self.load_data()
        if len(self.class_names) < 3:
            return 1
        _, pval = stats.friedmanchisquare(
            *(data.iloc[:, i] for i in range(len(self.class_names))))
        return pval

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
        ax.set_ylabel("Time [s]")
        ax.set_xlabel("Class index")
        canvas.print_figure(join(self.output, "box_plot.png"),
                            bbox_inches="tight")

    def scatter_plot(self):
        """Generate scatter plot showing how the measurement went."""
        if not self.draw_scatter_plot:
            return None
        data = self.load_data()

        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        ax = fig.add_subplot(1, 1, 1)
        ax.plot(data, ".", fillstyle='none', alpha=0.6)

        ax.set_title("Scatter plot")
        ax.set_ylabel("Time [s]")
        ax.set_xlabel("Sample index")
        ax.set_yscale("log")
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

    def diff_scatter_plot(self):
        """Generate scatter plot showing differences between samples."""
        if not self.draw_scatter_plot:
            return
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
        axes.set_ylabel("Time [s]")
        axes.set_xlabel("Sample index")
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

    def ecdf_plot(self):
        """Generate ECDF plot comparing distributions of the test classes."""
        if not self.draw_ecdf_plot:
            return None
        data = self.load_data()
        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        ax = fig.add_subplot(1, 1, 1)
        for classname in data:
            values = data.loc[:, classname]
            levels = np.linspace(1. / len(values), 1, len(values))
            ax.step(sorted(values), levels, where='post')
        self.make_legend(ax)
        ax.set_title("Empirical Cumulative Distribution Function")
        ax.set_xlabel("Time [s]")
        ax.set_ylabel("Cumulative probability")
        canvas.print_figure(join(self.output, "ecdf_plot.png"),
                            bbox_inches="tight")
        quant = np.quantile(values, [0.01, 0.95])
        quant[0] *= 0.98
        quant[1] *= 1.02
        ax.set_xlim(quant)
        canvas.print_figure(join(self.output, "ecdf_plot_zoom_in.png"),
                            bbox_inches="tight")

    def diff_ecdf_plot(self):
        """Generate ECDF plot of differences between test classes."""
        if not self.draw_ecdf_plot:
            return
        data = self.load_data()
        fig = Figure(figsize=(16, 12))
        canvas = FigureCanvas(fig)
        axes = fig.add_subplot(1, 1, 1)
        classnames = iter(data)
        base = next(classnames)
        base_data = data.loc[:, base]

        # parameters for the zoomed-in graphs of ecdf
        zoom_params = OrderedDict([("98", (0.01, 0.99)),
                                   ("33", (0.33, 0.66)),
                                   ("10", (0.45, 0.55))])
        zoom_values = OrderedDict((name, [float("inf"), float("-inf")])
                                  for name in zoom_params.keys())

        for classname in classnames:
            # calculate the ECDF
            values = data.loc[:, classname]
            levels = np.linspace(1. / len(values), 1, len(values))
            values = sorted(values-base_data)
            axes.step(values, levels, where='post')

            # calculate the bounds for the zoom positions
            quantiles = np.quantile(values, list(chain(*zoom_params.values())))
            quantiles = iter(quantiles)
            for low, high, name in \
                    zip(quantiles, quantiles, zoom_params.keys()):
                zoom_values[name][0] = min(zoom_values[name][0], low)
                zoom_values[name][1] = max(zoom_values[name][1], high)

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

        canvas.print_figure(join(self.output, "diff_ecdf_plot.png"),
                            bbox_inches="tight")

        # now graph progressive zooms of the central portion
        for name, quantiles, values in \
                zip(zoom_params.keys(), zoom_params.values(),
                    zoom_values.values()):
            axes.set_ylim(quantiles)
            # make the bounds a little weaker so that the extreme positions
            # are visible of graph too
            axes.set_xlim([values[0]*0.98, values[1]*1.02])
            canvas.print_figure(join(self.output,
                                     "diff_ecdf_plot_zoom_in_{0}.png"
                                     .format(name)),
                                bbox_inches="tight")

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
        Calculate mean, median, trimmed means (5% and 25%) and trimean with
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
                        (q1+2*median+q3)/4))
        return ret

    def _bootstrap_differences(self, pair, reps=5000):
        """Return a list of bootstrapped central tendencies of differences."""
        # don't pickle the diffs as they are read-only, use a global to pass
        # it to workers
        global _diffs
        # because the samples are not independent, we calculate mean of
        # differences not a difference of means
        data = self.load_data()
        _diffs = data.iloc[:, pair.index2] -\
            data.iloc[:, pair.index1]

        job_size = os.cpu_count() * 10

        keys = ("mean", "median", "trim_mean_05", "trim_mean_25", "trimean")

        ret = dict((k, list()) for k in keys)

        with mp.Pool() as pool:
            cent_tend = pool.imap_unordered(
                self._cent_tend_of_random_sample,
                chain(repeat(job_size, reps//job_size), [reps % job_size]))

            for values in cent_tend:
                # handle reps % job_size == 0
                if not values:
                    continue
                # transpose the results so that they can be added to lists
                chunk = list(map(list, zip(*values)))
                for key, i in zip(keys, range(5)):
                    ret[key].extend(chunk[i])
        _diffs = None
        return ret

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
            estimate of mean, median, trimmed mean (5% and 25%) and trimean
            of differences of observations
        """
        cent_tend = self._bootstrap_differences(pair, reps)

        data = self.load_data()
        diff = data.iloc[:, pair.index2] - data.iloc[:, pair.index1]
        mean = np.mean(diff)
        q1, median, q3 = np.quantile(diff, [0.25, 0.5, 0.75])
        trim_mean_05 = stats.trim_mean(diff, 0.05, 0)
        trim_mean_25 = stats.trim_mean(diff, 0.25, 0)
        trimean = (q1 + 2*median + q3)/4

        quantiles = [(1-ci)/2, 1-(1-ci)/2]

        exact_values = {"mean": mean, "median": median,
                        "trim_mean_05": trim_mean_05,
                        "trim_mean_25": trim_mean_25,
                        "trimean": trimean}

        ret = {}
        for key, value in exact_values.items():
            calc_quant = np.quantile(cent_tend[key], quantiles)
            ret[key] = (calc_quant[0], value, calc_quant[1])
        return ret

    def conf_interval_plot(self):
        """Generate the confidence inteval for differences between samples."""
        if not self.draw_conf_interval_plot:
            return

        reps = 5000
        boots = {"mean": pd.DataFrame(),
                 "median": pd.DataFrame(),
                 "trim mean (5%)": pd.DataFrame(),
                 "trim mean (25%)": pd.DataFrame(),
                 "trimean": pd.DataFrame()}

        for i in range(1, len(self.class_names)):
            pair = TestPair(0, i)
            diffs = self._bootstrap_differences(pair, reps)

            boots["mean"]['{}-0'.format(i)] = diffs["mean"]
            boots["median"]['{}-0'.format(i)] = diffs["median"]
            boots["trim mean (5%)"]['{}-0'.format(i)] = diffs["trim_mean_05"]
            boots["trim mean (25%)"]['{}-0'.format(i)] = diffs["trim_mean_25"]
            boots["trimean"]['{}-0'.format(i)] = diffs["trimean"]

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

            if name == "trim mean (5%)":
                name = "trim_mean_05"
            elif name == "trim mean (25%)":
                name = "trim_mean_25"

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

    def desc_stats(self):
        """Calculate the descriptive statistics for sample differences."""
        data = self.load_data()
        results = {}
        comb = combinations(list(range(len(self.class_names))), 2)
        for index1, index2, in comb:
            data1 = data.iloc[:, index1]
            data2 = data.iloc[:, index2]

            diff = data2 - data1

            diff_stats = {}
            diff_stats["mean"] = np.mean(diff)
            diff_stats["SD"] = np.std(diff)
            quantiles = np.quantile(diff, [0.25, 0.5, 0.75])
            diff_stats["median"] = quantiles[1]
            diff_stats["IQR"] = quantiles[2] - quantiles[1]
            diff_stats["MAD"] = stats.median_abs_deviation(diff)
            results[TestPair(index1, index2)] = diff_stats
        return results

    @staticmethod
    def _write_stats(name, low, med, high, txt_file):
        txt = "{} of differences: {:.5e}s, 95% CI: {:.5e}s, {:5e}s (±{:.3e}s)"\
            .format(name, med, low, high, (high-low)/2)
        print(txt)
        txt_file.write(txt + "\n")

    def _write_individual_results(self):
        """Write results to report.csv"""
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
            for pair, result in box_results.items():
                index1 = pair.index1
                index2 = pair.index2
                diff_stats = desc_stats[pair]
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

                # if both tests or the sign test found a difference
                # consider it a possible side-channel
                if result and wilcox_results[pair] < 0.05 or \
                        sign_results[pair] < 0.05:
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

        return difference, p_vals, sign_p_vals, worst_pair, worst_p

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

    def _write_summary(self, difference, p_vals, sign_p_vals, worst_pair,
                       worst_p, friedman_p):
        """Write the report.txt file and print summary."""
        report_filename = join(self.output, "report.csv")
        text_report_filename = join(self.output, "report.txt")
        with open(text_report_filename, 'w') as txt_file:
            txt_file.write(
                "tlsfuzzer analyse.py version {0} analysis\n"
                .format(VERSION))

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

            _, p = stats.kstest(sign_p_vals, 'uniform')
            txt = "KS-test for uniformity of p-values from sign test "
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            txt = "p-value: {}".format(p)
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            txt = ("Sign test mean p-value: {}, median p-value: {}"
                   .format(np.mean(sign_p_vals), np.median(sign_p_vals)))
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            # fail the overall test only when p-values from sign test
            # are not uniform AND are skewed to the left
            if p < 0.05 and np.mean(sign_p_vals) < 0.5:
                difference = 1

            txt = "Friedman test (chisquare approximation) for all samples"
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            txt = "p-value: {}".format(friedman_p)
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')
            if friedman_p < 0.05:
                difference = 1

            txt = "Worst pair: {}({}), {}({})".format(
                worst_pair.index1,
                self.class_names[worst_pair.index1],
                worst_pair.index2,
                self.class_names[worst_pair.index2])
            print(txt)
            txt_file.write(txt)
            txt_file.write('\n')

            diff_conf_int = self.calc_diff_conf_int(worst_pair)
            # use 95% CI as that translates to 2 standard deviations, making
            # it easy to estimate higher CIs
            for name, key in (("Mean", "mean"), ("Median", "median"),
                              ("Trimmed mean (5%)", "trim_mean_05"),
                              ("Trimmed mean (25%)", "trim_mean_25"),
                              ("Trimean", "trimean")):
                self._write_stats(
                    name,
                    diff_conf_int[key][0], diff_conf_int[key][1],
                    diff_conf_int[key][2], txt_file)

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

        for proc, err_desc in threads:
            self._stop_thread(proc, err_desc)

    def generate_report(self):
        """
        Compiles a report consisting of statistical tests and plots.

        :return: int 0 if no difference was detected, 1 otherwise
        """
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

        friedman_result = self.friedman_test()

        difference, p_vals, sign_p_vals, worst_pair, worst_p = \
            self._write_individual_results()

        difference = self._write_summary(difference, p_vals, sign_p_vals,
                                         worst_pair,
                                         worst_p, friedman_result)

        self._stop_all_threads(processes)

        return difference


# exclude from coverage as it's a). trivial, and b). not easy to test
if __name__ == '__main__':  # pragma: no cover
    ret = main()
    print("Analysis return value: {}".format(ret))
    sys.exit(ret)
