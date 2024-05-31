# Author: Jan Koscielniak, (c) 2020
# Released under Gnu GPL v2.0, see LICENSE file for details
try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
except ImportError:
    import unittest.mock as mock

import struct
import sys
import os
import tempfile
from collections import defaultdict

failed_import = False
try:
    from tlsfuzzer.analysis import Analysis, main, TestPair, help_msg
    import pandas as pd
    import numpy as np
    import multiprocessing as mp
except ImportError:
    failed_import = True

import random


@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestReport(unittest.TestCase):
    def setUp(self):
        data = {
            'A': [0.000758129, 0.000696719, 0.000980079, 0.000988900, 0.000875509,
                0.000734843, 0.000754852, 0.000667378, 0.000671230, 0.000790935],
            'B': [0.000758130, 0.000696718, 0.000980080, 0.000988899, 0.000875510,
                0.000734843, 0.000754852, 0.000667378, 0.000671230, 0.000790935],
            'C': [0.000758131, 0.000696717, 0.000980081, 0.000988898, 0.000875511,
                0.000734843, 0.000754852, 0.000667378, 0.000671230, 0.000790935]
        }
        self.neq_data = pd.DataFrame(data={
            'A': [0.000758130, 0.000696718, 0.000980080, 0.000988899, 0.000875510,
                0.000734843, 0.000754852, 0.000667378, 0.000671230, 0.000790935],
            'B': [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            'C': [0.11, 0.21, 0.31, 0.41, 0.51, 0.61, 0.71, 0.81, 0.91, 1.01]
        })
        self.neq_data_overlap = pd.DataFrame(data={
            'A': [0, 0, 1, 7, 7] + [7] * 95,
            'B': [0, 0, 2, 6, 7] + [7] * 95,
        })
        self.timings = pd.DataFrame(data=data)
        self.mock_read_csv = mock.Mock()
        self.mock_read_csv.return_value = self.timings

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("builtins.print")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    def test_report(
        self, mock_ecdf, mock_diff_ecdf, mock_box, mock_scatter,
        mock_diff_scatter, mock_conf_int, mock_graph_worst_pair,
        mock_load_data, mock_print, mock_open, mock_convert_to_binary,
    ):
        mock_load_data.return_value = self.timings

        analysis = Analysis("/tmp", verbose=True)
        ret = analysis.generate_report()

        mock_load_data.assert_called()
        #mock_ecdf.assert_called_once()
        #mock_box.assert_called_once()
        #mock_scatter.assert_called_once()
        # we're writing to report.csv, legend.csv,
        # sample_stats.csv, and report.txt
        self.assertEqual(mock_open.call_count, 4)
        self.assertEqual(ret, 0)

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_multithreaded(
        self, mock_read_csv, mock_ecdf, mock_box, mock_scatter,
        mock_diff_scatter, mock_conf_int, mock_diff_ecdf_plot,
        mock_graph_worst_pair, mock_open, mock_print, mock_convert_to_binary,
    ):
        mock_read_csv.return_value = self.timings

        analysis = Analysis("/tmp",
            multithreaded_graph=True)
        ret = analysis.generate_report()

        mock_read_csv.assert_called()
        #mock_ecdf.assert_called_once()
        #mock_box.assert_called_once()
        #mock_scatter.assert_called_once()
        # we're writing to report.csv, legend.csv,
        # sample_stats.csv, and report.txt
        self.assertEqual(mock_open.call_count, 4)
        self.assertEqual(ret, 0)

    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("scipy.stats.friedmanchisquare")
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_neq(
        self, mock_read_csv, mock_ecdf, mock_diff_ecdf, mock_box, mock_scatter,
        mock_diff_scatter, mock_conf_int, mock_worst_pair, mock_friedman,
        mock_open, mock_print
    ):
        timings = pd.DataFrame(data=self.neq_data)
        mock_read_csv.return_value = timings
        mock_friedman.return_value = (None, 0.55)

        analysis = Analysis("/tmp")
        ret = analysis.generate_report()

        mock_read_csv.assert_called()
        #mock_ecdf.assert_called_once()
        #mock_box.assert_called_once()
        #mock_scatter.assert_called_once()
        # we're writing to report.csv, legend.csv,
        # sample_stats.csv, and report.txt
        self.assertEqual(mock_open.call_count, 4)
        self.assertEqual(ret, 1)

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_error_in_box_plot(
        self, mock_read_csv, mock_ecdf, mock_box, mock_scatter, mock_conf_int,
        mock_graph_worst_pair, mock_open, mock_print, mock_convert_to_bin
    ):
        mock_read_csv.return_value = self.timings
        mock_box.side_effect = Exception("Test")

        analysis = Analysis("/tmp")

        with self.assertRaises(Exception) as exc:
            ret = analysis.generate_report()

        self.assertIn("Box plot graph", str(exc.exception))

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_error_in_scatter_plot(
        self, mock_read_csv, mock_ecdf, mock_box, mock_scatter, mock_conf_int,
        mock_graph_worst_pair, mock_open, mock_print, mock_convert_to_bin,
    ):
        mock_read_csv.return_value = self.timings
        mock_scatter.side_effect = Exception("Test")

        analysis = Analysis("/tmp")

        with self.assertRaises(Exception) as exc:
            ret = analysis.generate_report()

        self.assertIn("Scatter plot graph", str(exc.exception))

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_error_in_ecdf_plot(
        self, mock_read_csv, mock_ecdf, mock_box, mock_scatter, mock_conf_int,
        mock_graph_worst_pair, mock_open, mock_print, mock_convert_to_bin,
    ):
        mock_read_csv.return_value = self.timings
        mock_ecdf.side_effect = Exception("Test")

        analysis = Analysis("/tmp")

        with self.assertRaises(Exception) as exc:
            ret = analysis.generate_report()

        self.assertIn("ECDF graph", str(exc.exception))

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_error_in_conf_interval_plot(
        self, mock_read_csv, mock_ecdf, mock_box, mock_scatter, mock_conf_int,
        mock_graph_worst_pair, mock_open, mock_print, mock_convert_to_bin,
    ):
        mock_read_csv.return_value = self.timings
        mock_conf_int.side_effect = Exception("Test")

        analysis = Analysis("/tmp")

        with self.assertRaises(Exception) as exc:
            ret = analysis.generate_report()

        self.assertIn("Conf interval graph", str(exc.exception))

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_error_in_MT_box_plot(
        self, mock_read_csv, mock_ecdf, mock_box, mock_scatter,
        mock_diff_scatter_plot, mock_diff_ecdf, mock_conf_int,
        mock_graph_worst_pair, mock_open, mock_print, mock_conv_to_binary,
    ):
        mock_read_csv.return_value = self.timings
        mock_box.side_effect = Exception("Test")

        analysis = Analysis("/tmp", multithreaded_graph=True)

        with self.assertRaises(Exception) as exc:
            ret = analysis.generate_report()

        self.assertIn("Box plot graph", str(exc.exception))

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_error_in_MT_scatter_plot(
        self, mock_read_csv, mock_ecdf, mock_diff_ecdf, mock_box, mock_scatter,
        mock_diff_scatter, mock_conf_int, mock_graph_worst, mock_open,
        mock_print, mock_conv_to_bin,
    ):
        mock_read_csv.return_value = self.timings
        mock_scatter.side_effect = Exception("Test")

        analysis = Analysis("/tmp", multithreaded_graph=True)

        with self.assertRaises(Exception) as exc:
            ret = analysis.generate_report()

        self.assertIn("Scatter plot graph", str(exc.exception))

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_error_in_MT_ecdf_plot(
        self, mock_read_csv, mock_ecdf, mock_diff_ecdf_plot, mock_box,
        mock_scatter, mock_diff_scatter_plot, mock_conf_int,
        mock_graph_worst_pair, mock_open, mock_print, mock_conv_to_bin,
    ):
        mock_read_csv.return_value = self.timings
        mock_ecdf.side_effect = Exception("Test")

        analysis = Analysis("/tmp", multithreaded_graph=True)

        with self.assertRaises(Exception) as exc:
            ret = analysis.generate_report()

        self.assertIn("ECDF graph", str(exc.exception))

    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    @mock.patch("builtins.print")
    @mock.patch("__main__.__builtins__.open", new_callable=mock.mock_open)
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.box_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    def test_report_error_in_MT_conf_interval_plot(
        self, mock_read_csv, mock_ecdf, mock_diff_ecdf, mock_box, mock_scatter,
        mock_diff_scatter, mock_conf_int, mock_graph_worst_pair, mock_open,
        mock_print, mock_conv_to_bin,
    ):
        mock_read_csv.return_value = self.timings
        mock_conf_int.side_effect = Exception("Test")

        analysis = Analysis("/tmp", multithreaded_graph=True)

        with self.assertRaises(Exception) as exc:
            ret = analysis.generate_report()

        self.assertIn("Conf interval graph", str(exc.exception))

    @mock.patch("tlsfuzzer.analysis.Analysis._k_sizes_totals")
    @mock.patch("tlsfuzzer.analysis.Analysis._long_format_to_binary")
    @mock.patch("tlsfuzzer.analysis.Analysis._bit_size_write_summary")
    @mock.patch("tlsfuzzer.analysis.Analysis._bit_size_come_to_verdict")
    @mock.patch("tlsfuzzer.analysis.Analysis.analyze_bit_sizes")
    @mock.patch("tlsfuzzer.analysis.Analysis.skillings_mack_test")
    def test_report_bit_size(self, mock_skilling_mack, mock_bit_sizes,
            mock_verdict, mock_write_summary, mock_long_to_bin,
            mock_k_sizes_totals):
        mock_verdict.return_value = (0, "test")

        analysis = Analysis("/tmp", bit_size_analysis=True)
        ret = analysis.generate_report(bit_size=True)

        mock_long_to_bin.assert_called_once_with(
                "/tmp/measurements.csv",
                "/tmp/measurements.bin")
        mock_skilling_mack.assert_called_once_with("/tmp/measurements.bin")
        mock_bit_sizes.assert_called()
        mock_verdict.assert_called()
        mock_write_summary.assert_called()
        mock_k_sizes_totals.assert_called()
        self.assertEqual(ret, 0)

    @mock.patch("tlsfuzzer.analysis.Analysis.analyse_hamming_weights")
    @mock.patch("__main__.__builtins__.open")
    def test_report_hamming_weights(self, mock_open, mock_hamming_weights):
        report_text = "testing_hamming_weight_report"
        self.writen_text = ""
        mock_hamming_weights.return_value = 0

        def add_to_written(x):
            self.writen_text += x

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            r = mock.mock_open()(file_name, mode)

            if "w" in mode:
                r.write.side_effect = lambda s: (add_to_written(s))

            return r

        mock_open.side_effect = file_selector

        analysis = Analysis("/tmp", bit_size_analysis=True)
        analysis._hamming_weight_report = report_text
        ret = analysis.generate_report(hamming_weight=True)

        mock_hamming_weights.assert_called_once_with()
        self.assertEqual(ret, 0)
        self.assertEqual(self.writen_text, report_text)

    def test_setting_alpha(self):
        with mock.patch(
            "tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv
        ):
            analysis = Analysis("/tmp", alpha=1e-12)
            self.mock_read_csv.assert_called_once()

            self.assertEqual(analysis.alpha, 1e-12)

    def test_wilcoxon_test(self):
        with mock.patch(
            "tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv
        ):
            analysis = Analysis("/tmp")
            self.mock_read_csv.assert_called_once()

            res = analysis.wilcoxon_test()
            self.assertEqual(len(res), 3)
            for index, result in res.items():
                self.assertGreaterEqual(result, 0.25)

    def test__wilcox_test(self):
        pval = Analysis._wilcox_test(self.neq_data.iloc[:,0],
                                     self.neq_data.iloc[:,1])
        self.assertGreaterEqual(0.05, pval)

    def test_sign_test(self):
        with mock.patch(
            "tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv
        ):
            analysis = Analysis("/tmp")
            self.mock_read_csv.assert_called_once()

            res = analysis.sign_test()
            self.assertEqual(len(res), 3)
            for index, result in res.items():
                self.assertEqual(result, 1)

    def test__sign_test(self):
        pval = Analysis._sign_test(self.neq_data.iloc[:, 0],
                                   self.neq_data.iloc[:, 1],
                                   0, "two-sided")
        self.assertLess(pval, 0.002)

    def test_sign_test_with_alternative_less(self):
        with mock.patch(
            "tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv
        ):
            analysis = Analysis("/tmp")
            self.mock_read_csv.assert_called_once()

            res = analysis.sign_test(alternative="less")
            self.assertEqual(len(res), 3)
            for index, result in res.items():
                self.assertEqual(result, 0.5)

    def test_sign_test_with_alternative_less_and_neq_data(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data") as load_data:
            load_data.return_value = self.neq_data
            analysis = Analysis("/tmp")

            res = analysis.sign_test(alternative="less")
            self.assertEqual(len(res), 3)
            for index, result in res.items():
                self.assertLessEqual(result, 0.001)

    def test_sign_test_with_alternative_greater_and_neq_data(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data") as load_data:
            load_data.return_value = self.neq_data
            analysis = Analysis("/tmp")

            res = analysis.sign_test(alternative="greater")
            self.assertEqual(len(res), 3)
            for index, result in res.items():
                self.assertLessEqual(result, 1)

    def test_rel_t_test(self):
        with mock.patch(
            "tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv
        ):
            analysis = Analysis("/tmp")
            self.mock_read_csv.assert_called_once()

            res = analysis.rel_t_test()
            self.assertEqual(len(res), 3)
            for index, result in res.items():
                self.assertGreaterEqual(result, 0.25)

    def test__rel_t_test(self):
        pval = Analysis._rel_t_test(self.neq_data.iloc[:,0],
                                     self.neq_data.iloc[:,1])
        self.assertGreaterEqual(0.05, pval)

    def test_box_test(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            analysis = Analysis("/tmp")
            self.mock_read_csv.assert_called_once()

            res = analysis.box_test()
            self.assertEqual(len(res), 3)
            for index, result in res.items():
                self.assertEqual(result, None)

    def test__box_test_neq(self):
        ret = Analysis._box_test(self.neq_data.iloc[:,0],
                                 self.neq_data.iloc[:,1],
                                 0.03, 0.04)

        self.assertEqual(ret, '<')

    def test__box_test_neq_gt(self):
        ret = Analysis._box_test(self.neq_data.iloc[:,1],
                                 self.neq_data.iloc[:,0],
                                 0.03, 0.04)

        self.assertEqual(ret, '>')

    def test__box_test_overlap(self):
        ret = Analysis._box_test(self.neq_data.iloc[:,0],
                                 self.neq_data.iloc[:,0],
                                 0.03, 0.04)

        self.assertEqual(ret, None)

    def test_box_test_neq(self):
        timings = pd.DataFrame(data=self.neq_data)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            analysis = Analysis("/tmp")

            res = analysis.box_test()
            self.assertEqual(len(res), 3)
            for index, result in res.items():
                self.assertNotEqual(result, None)

    def test_box_test_neq_overlap(self):
        timings = pd.DataFrame(data=self.neq_data_overlap)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            analysis = Analysis("/tmp")
            mock_read_csv.assert_called_once()

            res = analysis.box_test()
            self.assertEqual(len(res), 1)
            for index, result in res.items():
                self.assertEqual(result, None)

    def test__cent_tend_of_random_sample(self):
        diffs = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        timings = pd.DataFrame(data=self.neq_data_overlap)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            with mock.patch("tlsfuzzer.analysis._diffs", diffs):
                analysis = Analysis("/tmp")
                vals = analysis._cent_tend_of_random_sample(10)

                self.assertEqual(len(vals), 10)
                means = [i[0] for i in vals]
                avg = sum(means)/len(means)
                self.assertLessEqual(avg, 8)
                self.assertLessEqual(2, avg)

    def test__cent_tend_of_random_sample_with_no_reps(self):
        diffs = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        timings = pd.DataFrame(data=self.neq_data_overlap)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            with mock.patch("tlsfuzzer.analysis._diffs", diffs):
                analysis = Analysis("/tmp")
                vals = analysis._cent_tend_of_random_sample(0)

                self.assertEqual(len(vals), 0)
                self.assertEqual(vals, [])

    def test__desc_stats(self):
        ret = Analysis._desc_stats(self.neq_data.iloc[:,0],
                                   self.neq_data.iloc[:,1])

        self.assertEqual(ret, {
            'mean': 0.5492081424999999,
            'SD': 0.28726800639941136,
            'median': 0.5491948234999999,
            'IQR': 0.45029303825,
            'MAD': 0.250156351})

    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    @mock.patch("builtins.open")
    def test__write_summary(self, mock_open, mock_load_data):
        mock_open.side_effect = mock.mock_open()

        fake_conf_ints = {
            'mean': (0, 0, 0),
            'median': (0, 0, 0),
            'trim_mean_05': (0, 0, 0),
            'trim_mean_25': (0, 0, 0),
            'trim_mean_45': (0, 0, 0),
            'trimean': (0, 0, 0)
        }

        tests = [
            (None, (0, 0, 0), 0, "Definite side-channel detected"),
            (1e-10, (0, 0, 0), 1, "Definite side-channel detected"),
            (1e-6, (0, 0, 0), 1, "Results suggesting side-channel found"),
            (1, (0, 0, 0), 0, "ERROR"),
            (1, (1e-11, 0, 2e-11), 0, "Implementation verified as not"),
            (1, (1e-10, 0, 6e-10), 0, "Implementation most likely not"),
            (1, (1e-3, 0, 2e-3), 0, "Large confidence intervals detected"),
            (1, (1, 0, 2), 0, "Very large confidence intervals detected"),
        ]

        analysis = Analysis("/tmp")
        analysis.class_names = {"0":"0", "1":"1"}
        analysis.alpha = 1e-5

        for test in tests:
            with mock.patch("builtins.print") as mock_print:
                fake_conf_ints['mean'] = test[1]
                difference = analysis._write_summary(
                    0, None, [1e-4, 1e-10, 1e-5, 1], ["0", "1"],
                    test[0], fake_conf_ints
                )
                self.assertEqual(difference, test[2])
                for i in mock_print.mock_calls:
                    if test[3] in str(i):
                        break
                else:
                    self.assertTrue(False)



@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestFriedmanNegative(unittest.TestCase):
    def setUp(self):
        data = {
            'A': np.random.normal(size=1000),
            'B': np.random.normal(size=1000),
            'C': np.random.normal(size=1000)
        }
        timings = pd.DataFrame(data=data)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            self.analysis = Analysis("/tmp", verbose=True)
        self.analysis.load_data = mock_read_csv

    @mock.patch("builtins.print")
    def test_friedman_negative(self, print_fun):
        friedman_result = mp.Queue()
        self.analysis.friedman_test(friedman_result)

        result = friedman_result.get()

        self.assertTrue(result > 1e-6)


@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestFriedmanInvalid(unittest.TestCase):
    def setUp(self):
        data = {
            'A': np.random.normal(size=10),
            'B': np.random.normal(size=10),
        }
        timings = pd.DataFrame(data=data)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            self.analysis = Analysis("/tmp")
        self.analysis.load_data = mock_read_csv

    def test_friedman_negative(self):
        friedman_result = mp.Queue()
        self.analysis.friedman_test(friedman_result)

        result = friedman_result.get()

        self.assertIsNone(result)


@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestPlots(unittest.TestCase):
    def setUp(self):
        data = {
            'A': [0.000758130, 0.000696718, 0.000980080, 0.000988899, 0.000875510,
                0.000734843, 0.000754852, 0.000667378, 0.000671230, 0.000790935],
            'B': [0.000758130, 0.000696718, 0.000980080, 0.000988899, 0.000875510,
                0.000734843, 0.000754852, 0.000667378, 0.000671230, 0.000790935]
        }
        timings = pd.DataFrame(data=data)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            self.analysis = Analysis("/tmp")
        self.analysis.load_data = mock_read_csv

    @mock.patch("builtins.print")
    def test_ecdf_plot(self, print_fun):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            self.analysis.verbose = True
            self.analysis.ecdf_plot()
            self.assertEqual(mock_save.call_args_list,
                [mock.call('/tmp/ecdf_plot.png', bbox_inches='tight'),
                 mock.call('/tmp/ecdf_plot_zoom_in.png', bbox_inches='tight')])

    @mock.patch("builtins.print")
    def test_diff_ecdf_plot(self, print_fun):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            self.analysis.verbose = True
            self.analysis.diff_ecdf_plot()
            self.assertEqual(mock_save.call_args_list,
                [mock.call('/tmp/diff_ecdf_plot.png', bbox_inches='tight'),
                 mock.call('/tmp/diff_ecdf_plot_zoom_in_98.png',
                            bbox_inches='tight'),
                 mock.call('/tmp/diff_ecdf_plot_zoom_in_33.png',
                            bbox_inches='tight'),
                 mock.call('/tmp/diff_ecdf_plot_zoom_in_10.png',
                            bbox_inches='tight')])

    @mock.patch("builtins.print")
    def test_scatter_plot(self, print_fun):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            self.analysis.verbose = True
            self.analysis.scatter_plot()
            self.assertEqual(mock_save.call_args_list,
                [mock.call('/tmp/scatter_plot.png', bbox_inches='tight'),
                 mock.call('/tmp/scatter_plot_zoom_in.png',
                           bbox_inches='tight')])

    @mock.patch("builtins.print")
    def test_diff_scatter_plot(self, print_fun):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            self.analysis.verbose = True
            self.analysis.diff_scatter_plot()
            self.assertEqual(mock_save.call_args_list,
                [mock.call('/tmp/diff_scatter_plot.png', bbox_inches='tight'),
                 mock.call('/tmp/diff_scatter_plot_zoom_in.png',
                           bbox_inches='tight')])

    @mock.patch("builtins.print")
    def test_box_plot(self, print_fun):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            with mock.patch("tlsfuzzer.analysis.Analysis._calc_percentiles")\
                    as mock_percentiles:
                self.analysis.verbose = True
                mock_percentiles.return_value = pd.DataFrame(
                    data={'A': [0.05, 0.25, 0.5, 0.75, 0.95],
                          'B': [0.55, 0.75, 1, 1.25, 1.45]})
                self.analysis.box_plot()
                mock_save.assert_called_once()
                mock_percentiles.assert_called_once_with()

    @mock.patch("tlsfuzzer.analysis.np.memmap")
    @mock.patch("tlsfuzzer.analysis.os.remove")
    @mock.patch("tlsfuzzer.analysis.shutil.copyfile")
    def test__calc_percentiles(self, mock_copyfile, mock_remove, mock_memmap):
        mock_memmap.return_value = self.analysis.load_data()

        ret = self.analysis._calc_percentiles()

        self.assertIsNotNone(ret)
        self.assertEqual(ret.values[0, 0], 0.0006691114)
        mock_copyfile.assert_called_once_with(
            "/tmp/timing.bin", "/tmp/.quantiles.tmp")
        mock_remove.assert_called_once_with("/tmp/.quantiles.tmp")

    @mock.patch("builtins.print")
    def test_conf_interval_plot(self, print_fun):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            with mock.patch("__main__.__builtins__.open", mock.mock_open())\
                    as mock_open:
                self.analysis.verbose = True
                self.analysis.conf_interval_plot()
                self.assertEqual(mock_save.call_args_list,
                    [mock.call('/tmp/conf_interval_plot_mean.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/conf_interval_plot_median.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/conf_interval_plot_trim_mean_05.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/conf_interval_plot_trim_mean_25.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/conf_interval_plot_trim_mean_45.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/conf_interval_plot_trimean.png',
                               bbox_inches='tight')])


@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestMediumPlots(unittest.TestCase):
    def setUp(self):
        data = {
            'A': np.random.normal(size=10000),
            'B': np.random.normal(size=10000)
        }
        timings = pd.DataFrame(data=data)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            self.analysis = Analysis("/tmp", verbose=True)
        self.analysis.load_data = mock_read_csv

    @mock.patch("builtins.print")
    def test_graph_worst_pair(self, print_fun):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            with mock.patch("__main__.__builtins__.open", mock.mock_open())\
                    as mock_open:
                self.analysis.graph_worst_pair((0, 1))
                self.assertEqual(mock_save.call_args_list,
                    [mock.call('/tmp/sample_0_heatmap.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/sample_0_heatmap_zoom_in.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/sample_1_heatmap.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/sample_1_heatmap_zoom_in.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/worst_pair_diff_heatmap.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/worst_pair_diff_heatmap_zoom_in.png',
                               bbox_inches='tight')])


@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestLargePlots(unittest.TestCase):
    def setUp(self):
        data = {
            'A': np.random.normal(size=150000),
            'B': np.random.normal(size=150000)
        }
        timings = pd.DataFrame(data=data)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            self.analysis = Analysis("/tmp")
        self.analysis.load_data = mock_read_csv

    def test_graph_worst_pair(self):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            with mock.patch("__main__.__builtins__.open", mock.mock_open())\
                    as mock_open:
                self.analysis.graph_worst_pair((0, 1))
                self.assertEqual(mock_save.call_args_list,
                    [mock.call('/tmp/sample_0_heatmap.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/sample_0_heatmap_zoom_in.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/sample_1_heatmap.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/sample_1_heatmap_zoom_in.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/sample_0_partial_heatmap_zoom_in.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/sample_1_partial_heatmap_zoom_in.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/worst_pair_diff_heatmap.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/worst_pair_diff_heatmap_zoom_in.png',
                               bbox_inches='tight'),
                     mock.call('/tmp/'
                               'worst_pair_diff_partial_heatmap_zoom_in.png',
                               bbox_inches='tight')])


@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestCommandLine(unittest.TestCase):
    def test_command_line(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.analysis.Analysis.generate_report') as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        None, None, None, False, True, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_delay_and_CR(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, '--status-delay', '3.5',
                '--status-newline']
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.analysis.Analysis.generate_report') as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        None, 3.5, '\n', False, True, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_workers(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, '--workers', '200']
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.analysis.Analysis.generate_report') as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        200, None, None, False, True, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_verbose(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--verbose"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.analysis.Analysis.generate_report') as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, True, None, None,
                        None, None, None, False, True, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_multithreaded_plots(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--multithreaded-graph"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.analysis.Analysis.generate_report') as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, True, False, None, None,
                        None, None, None, False, True, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_no_plots(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--no-ecdf-plot",
                "--no-scatter-plot", "--no-conf-interval-plot"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.analysis.Analysis.generate_report') as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, False, False, False, False, False, None, None,
                        None, None, None, False, True, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_frequency(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--clock-frequency", "10.0"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.analysis.Analysis.generate_report') as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, 10*1e6, None,
                        None, None, None, False, True, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_alpha(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--alpha", "1e-3"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch('tlsfuzzer.analysis.Analysis.generate_report') as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, 1e-3,
                        None, None, None, False, True, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_bit_size_measurements(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--bit-size"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch(
            'tlsfuzzer.analysis.Analysis.generate_report'
        ) as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        None, None, None, True, True, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_skip_sanity(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--bit-size", "--skip-sanity"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch(
            'tlsfuzzer.analysis.Analysis.generate_report'
        ) as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        None, None, None, True, True, 1e-09, 4,
                        'measurements.csv', True, True, True, True)

    def test_call_with_custom_measurements_filename(self):
        output = "/tmp"
        measurements_filename = "measurements-invert.csv"
        args = ["analysis.py", "-o", output, "--bit-size", "--measurements",
                 measurements_filename]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch(
            'tlsfuzzer.analysis.Analysis.generate_report'
        ) as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        None, None, None, True, True, 1e-09, 4,
                        measurements_filename, False, True, True, True)

    def test_call_with_no_smart_analysis(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--bit-size",
                "--no-smart-analysis"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch(
            'tlsfuzzer.analysis.Analysis.generate_report'
        ) as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        None, None, None, True, False, 1e-09, 4,
                        'measurements.csv', False, True, True, True)

    def test_call_with_parametrized_smart_analysis(self):
        output = "/tmp"
        bit_size_desire_ci = 5
        bit_recognition_size = 2
        args = ["analysis.py", "-o", output, "--bit-size",
                "--bit-size-desired-ci", bit_size_desire_ci,
                "--bit-recognition-size", bit_recognition_size,]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch(
            'tlsfuzzer.analysis.Analysis.generate_report'
        ) as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_report.assert_called_once()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        None, None, None, True, True,
                        bit_size_desire_ci * 1e-9, bit_recognition_size,
                        'measurements.csv', False, True, True, True)

    def test_call_with_Hamming_weight(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--Hamming-weight"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch(
            'tlsfuzzer.analysis.Analysis.generate_report'
        ) as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        None, None, None, True, True, 1e-9, 4,
                        'measurements.csv', False, True, True, True)
                    mock_report.assert_called_once_with(
                        bit_size=False, hamming_weight=True)

    def test_call_Hamming_weight_with_minimal_analysis(self):
        output = "/tmp"
        args = ["analysis.py", "-o", output, "--Hamming-weight",
                "--no-sign-test", "--no-t-test", "--no-wilcoxon-test"]
        mock_init = mock.Mock()
        mock_init.return_value = None
        with mock.patch(
            'tlsfuzzer.analysis.Analysis.generate_report'
        ) as mock_report:
            with mock.patch('tlsfuzzer.analysis.Analysis.__init__', mock_init):
                with mock.patch("sys.argv", args):
                    main()
                    mock_init.assert_called_once_with(
                        output, True, True, True, False, False, None, None,
                        None, None, None, True, True, 1e-9, 4,
                        'measurements.csv', False, False, False, False)
                    mock_report.assert_called_once_with(
                        bit_size=False, hamming_weight=True)

    def test_help(self):
        args = ["analysis.py", "--help"]
        with mock.patch('tlsfuzzer.analysis.help_msg') as help_mock:
            with mock.patch("sys.argv", args):
                self.assertRaises(SystemExit, main)
                help_mock.assert_called_once()

    def test_help_msg(self):
        with mock.patch('__main__.__builtins__.print') as print_mock:
            help_msg()
            self.assertGreaterEqual(print_mock.call_count, 1)

    def test_missing_output(self):
        args = ["analysis.py"]
        with mock.patch("sys.argv", args):
            self.assertRaises(ValueError, main)


@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestDataLoad(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.data = {
            'A': [0.000758130, 0.000696718, 0.000980080, 0.000988899,
                  0.000875510, 0.000734843, 0.000754852, 0.000667378,
                  0.000671230, 0.000790935],
            'B': [0.000758130, 0.000696718, 0.000980080, 0.000988899,
                  0.000875510, 0.000734843, 0.000754852, 0.000667378,
                  0.000671230, 0.000790935]
        }
        cls.df = pd.DataFrame(data=cls.data)
        cls.legend = {
            'ID': [0, 1],
            'Name': ['A', 'B']
        }

    @staticmethod
    def file_selector(name, mode="r"):
        if name == "/tmp/timing.bin.shape":
            return mock.mock_open(read_data="nrow,ncol\n10,2")(name, mode)
        if name == "/tmp/legend.csv":
            print("called with legend.csv")
            return mock.mock_open(read_data="ID,Name\n0,A\n1,B")(name, mode)
        return mock.mock_open(name, mode)

    @mock.patch("tlsfuzzer.analysis.np.memmap")
    @mock.patch("tlsfuzzer.analysis.pd.read_csv")
    @mock.patch("builtins.open")
    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    def test_load_data(self, convert_mock, open_mock, read_csv_mock,
            memmap_mock):
        open_mock.side_effect = self.file_selector
        read_csv_mock.return_value = pd.DataFrame(data=self.legend)
        memmap_mock.return_value = self.df.values

        a = Analysis("/tmp")

        self.assertTrue(a.load_data().equals(self.df))

        convert_mock.assert_called_with()
        read_csv_mock.assert_called_with("/tmp/legend.csv")
        memmap_mock.assert_called_with(
            "/tmp/timing.bin", dtype=np.float64, mode="r", shape=(10, 2),
            order="C")

    @mock.patch("builtins.open")
    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    def test_load_data_with_wrong_shape_file(self, convert_mock, open_mock):
        open_mock.side_effect = lambda a, b:\
            mock.mock_open(read_data="som,wrong,file\n1,2,3")(a, b)

        with self.assertRaises(ValueError) as err:
            Analysis("/tmp")

        self.assertIn("Malformed /tmp/timing.bin.shape ", str(err.exception))
        convert_mock.assert_called_once()

    @mock.patch("tlsfuzzer.analysis.pd.read_csv")
    @mock.patch("builtins.open")
    @mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary")
    def test_load_data_with_inconsistent_legend_and_shape(self, convert_mock,
            open_mock, read_csv_mock):
        open_mock.side_effect = self.file_selector
        read_csv_mock.return_value = pd.DataFrame(data=
            {"A": [0, 1, 2], "B": [0, 1, 2], "C": [3, 4, 5]})

        with self.assertRaises(ValueError) as err:
            Analysis("/tmp")

        self.assertIn("Inconsistent /tmp/legend.csv and /tmp/timing.bin.shape",
                      str(err.exception))
        convert_mock.assert_called_once()
        read_csv_mock.assert_called_once()

    @mock.patch("tlsfuzzer.analysis.os.path.getmtime")
    @mock.patch("tlsfuzzer.analysis.os.path.isfile")
    @mock.patch("tlsfuzzer.analysis.np.memmap")
    @mock.patch("tlsfuzzer.analysis.pd.read_csv")
    @mock.patch("builtins.open")
    def test__convert_to_binary_with_noop(self, open_mock, read_csv_mock,
            memmap_mock, isfile_mock, getmtime_mock):
        open_mock.side_effect = self.file_selector
        read_csv_mock.return_value = pd.DataFrame(data=self.legend)
        memmap_mock.return_value = self.df.values
        isfile_mock.return_value = True
        getmtime_mock.side_effect = lambda f_name: \
            1 if f_name == "/tmp/timing.bin" else 0

        a = Analysis("/tmp")

        self.assertTrue(a.load_data().equals(self.df))

        read_csv_mock.assert_called_with("/tmp/legend.csv")
        memmap_mock.assert_called_with(
            "/tmp/timing.bin", dtype=np.float64, mode="r", shape=(10, 2),
            order="C")
        self.assertEqual(isfile_mock.call_args_list,
            [mock.call("/tmp/timing.bin"),
             mock.call("/tmp/legend.csv"),
             mock.call("/tmp/timing.bin.shape"),
             mock.call("/tmp/timing.bin"),
             mock.call("/tmp/legend.csv"),
             mock.call("/tmp/timing.bin.shape")])

    @staticmethod
    def mock_memmap(name, dtype, mode, shape, order):
        return np.empty(shape, dtype, order)

    @mock.patch("tlsfuzzer.analysis.np.memmap")
    @mock.patch("builtins.open")
    @mock.patch("tlsfuzzer.analysis.pd.read_csv")
    @mock.patch("tlsfuzzer.analysis.os.path.getmtime")
    @mock.patch("tlsfuzzer.analysis.os.path.isfile")
    def test__convert_to_binary_refresh(self, isfile_mock, getmtime_mock,
            read_csv_mock, open_mock, memmap_mock):
        isfile_mock.return_value = True
        getmtime_mock.return_value = 0
        read_csv_mock.side_effect = lambda _, chunksize, dtype: \
            iter(self.df[i:i+1] for i in range(self.df.shape[0]))
        open_mock.side_effect = self.file_selector
        memmap_mock.side_effect = self.mock_memmap

        a = Analysis.__new__(Analysis)
        a.output = "/tmp"
        a.verbose = False
        a.clock_frequency = None

        a._convert_to_binary()

    @mock.patch("tlsfuzzer.analysis.np.memmap")
    @mock.patch("builtins.open")
    @mock.patch("tlsfuzzer.analysis.pd.read_csv")
    @mock.patch("tlsfuzzer.analysis.os.path.getmtime")
    @mock.patch("tlsfuzzer.analysis.os.path.isfile")
    def test__convert_to_binary_custom_freq(self, isfile_mock, getmtime_mock,
            read_csv_mock, open_mock, memmap_mock):
        isfile_mock.return_value = True
        getmtime_mock.return_value = 0
        read_csv_mock.side_effect = lambda _, chunksize, dtype: \
            iter(self.df[i:i+1] for i in range(self.df.shape[0]))
        open_mock.side_effect = self.file_selector
        memmap_mock.side_effect = self.mock_memmap

        a = Analysis.__new__(Analysis)
        a.output = "/tmp"
        a.verbose = False
        a.clock_frequency = 1e-5

        a._convert_to_binary()

    @mock.patch("tlsfuzzer.analysis.np.memmap")
    @mock.patch("builtins.open")
    @mock.patch("tlsfuzzer.analysis.pd.read_csv")
    @mock.patch("tlsfuzzer.analysis.os.path.getmtime")
    @mock.patch("tlsfuzzer.analysis.os.path.isfile")
    @mock.patch("builtins.print")
    def test__convert_to_binary_refresh_verbose(self, print_mock, isfile_mock,
            getmtime_mock, read_csv_mock, open_mock, memmap_mock):
        isfile_mock.return_value = True
        getmtime_mock.return_value = 0
        read_csv_mock.side_effect = lambda _, chunksize, dtype: \
            iter(self.df[i:i+1] for i in range(self.df.shape[0]))
        open_mock.side_effect = self.file_selector
        memmap_mock.side_effect = self.mock_memmap

        a = Analysis.__new__(Analysis)
        a.output = "/tmp"
        a.verbose = True
        a.clock_frequency = None

        a._convert_to_binary()

@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestBitSizeAnalysis(unittest.TestCase):
    def setUp(self):
        self.analysis = Analysis("/tmp", bit_size_analysis=True)
        self.builtin_open = open

        self.blocks = [
            0, 0, 1, 1, 1, 2, 2, 3, 3, 3, 3, 4, 4, 5, 5, 5, 6, 6, 7, 7, 7, 8,
            8, 8, 9, 9, 9, 10, 10, 11, 11, 12, 12, 12, 13, 13, 14, 14, 15, 15,
            15, 16, 16, 17, 17, 17, 18, 18, 19, 19
        ]
        self.groups = [
            256, 254, 256, 248, 250, 256, 255, 256, 254, 255, 251, 256, 255,
            256, 254, 255, 256, 255, 256, 255, 252, 256, 255, 253, 256, 255,
            249, 256, 255, 256, 254, 256, 255, 256, 256, 255, 256, 255, 256,
            253, 256, 256, 255, 256, 255, 256, 256, 254, 256, 253
        ]
        self.values = [
            1.3e-03, 8.4e-05, 1.0e-04, 8.7e-05, 8.5e-05, 9.1e-05, 8.4e-05,
            8.4e-05, 8.4e-05, 8.4e-05, 9.7e-05, 9.1e-05, 8.4e-05, 8.5e-05,
            8.4e-05, 8.7e-05, 8.3e-05, 9.2e-05, 9.3e-05, 8.4e-05, 8.4e-05,
            8.4e-05, 8.4e-05, 8.4e-05, 9.1e-05, 8.4e-05, 8.5e-05, 8.5e-05,
            9.1e-05, 8.4e-05, 8.5e-05, 8.4e-05, 8.4e-05, 8.4e-05, 8.5e-05,
            8.4e-05, 8.3e-05, 9.0e-05, 8.3e-05, 8.4e-05, 8.5e-05, 8.5e-05,
            1.1e-04, 9.0e-05, 8.5e-05, 8.4e-05, 8.4e-05, 8.4e-05, 8.49e-05,
            8.5e-05
        ]

    @mock.patch("tlsfuzzer.analysis.Analysis._figure_out_analysis_data_size")
    @mock.patch("tlsfuzzer.analysis.Analysis._calc_exact_values")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_plot_for_all_k")
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.wilcoxon_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.rel_t_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    @mock.patch("tlsfuzzer.analysis.Analysis.create_k_specific_dirs")
    @mock.patch("tlsfuzzer.analysis.shutil.rmtree")
    @mock.patch("builtins.open")
    def test_bit_size_measurement_analysis_main(self, open_mock, rmtree_mock,
            dir_creation_mock, load_data_mock, rel_t_test_mock,
            wilcoxon_test_mock, interval_plot_mock, ecdf_plot_mock,
            scatter_plot_mock, worst_pair_mock, conf_plot_mock,
            calc_values_mock, figure_out_mock):

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            if "w" in mode:
                return mock.mock_open()(file_name, mode)

            if "timing.csv" in file_name:
                k_size = file_name.split("/")[-2]
                return mock.mock_open(
                    read_data="256,{0}".format(k_size) +
                              ("\n0.5,0.4\n0.4,0.5" * 6)
                )(file_name, mode)

            return mock.mock_open(
                read_data="0,256,3\n0,255,102\n0,254,103\n1,256,4\n" +
                          "1,254,104\n1,253,105"
            )(file_name, mode)

        k_sizes =  {
            256: 1,
            255: 1,
            254: 2,
            253: 1
        }

        self.analysis._k_sizes = k_sizes
        open_mock.side_effect = file_selector
        dir_creation_mock.return_value = k_sizes
        rel_t_test_mock.return_value = {(0, 1): 0.5}
        wilcoxon_test_mock.return_value = {(0, 1): 0.5}

        class dotDict(dict):
            __getattr__ = dict.__getitem__

        binomtest_result = {"statistic": 0.5, "pvalue": 0.5}
        binomtest_mock = mock.Mock()

        calc_values_mock.return_value = {
            "mean": 0.5, "median": 0.5, "trim_mean_05": 0.5,
            "trim_mean_25": 0.5, "trim_mean_45": 0.5, "trimean": 0.5
        }

        try:
            with mock.patch(
                "tlsfuzzer.analysis.stats.binomtest", binomtest_mock
            ):
                binomtest_mock.return_value = dotDict(binomtest_result)
                self.analysis.analyze_bit_sizes()
        except AttributeError:
            with mock.patch(
                "tlsfuzzer.analysis.stats.binom_test", binomtest_mock
            ):
                binomtest_mock.return_value = binomtest_result["pvalue"]
                self.analysis.analyze_bit_sizes()

        binomtest_mock.assert_called()
        rel_t_test_mock.assert_called()
        wilcoxon_test_mock.assert_called()
        calc_values_mock.assert_called()

        self.analysis._k_sizes = None

    @mock.patch("tlsfuzzer.analysis.Analysis._figure_out_analysis_data_size")
    @mock.patch("tlsfuzzer.analysis.Analysis._calc_exact_values")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_plot_for_all_k")
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.wilcoxon_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.rel_t_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    @mock.patch("tlsfuzzer.analysis.Analysis.create_k_specific_dirs")
    @mock.patch("tlsfuzzer.analysis.shutil.rmtree")
    @mock.patch("builtins.open")
    def test_bit_size_measurement_analysis_main_2_samples(self, open_mock,
            rmtree_mock, dir_creation_mock, load_data_mock, rel_t_test_mock,
            wilcoxon_test_mock, interval_plot_mock, ecdf_plot_mock,
            scatter_plot_mock, worst_pair_mock, conf_plot_mock,
            calc_values_mock, figure_out_mock):

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            if "w" in mode:
                return mock.mock_open()(file_name, mode)

            if "timing.csv" in file_name:
                k_size = file_name.split("/")[-2]
                return mock.mock_open(
                    read_data="256,{0}".format(k_size) +
                              ("\n0.5,0.4\n0.4,0.5")
                )(file_name, mode)

            return mock.mock_open(
                read_data="0,256,3\n0,255,102\n0,254,103\n1,256,4\n" +
                          "1,254,104\n1,253,105"
            )(file_name, mode)

        k_sizes =  {
            256: 1,
            255: 1,
            254: 2,
            253: 1
        }

        self.analysis._k_sizes = k_sizes
        open_mock.side_effect = file_selector
        dir_creation_mock.return_value = k_sizes

        class dotDict(dict):
            __getattr__ = dict.__getitem__

        binomtest_mock = mock.Mock()

        calc_values_mock.return_value = {
            "mean": 0.5, "median": 0.5, "trim_mean_05": 0.5,
            "trim_mean_25": 0.5, "trim_mean_45": 0.5, "trimean": 0.5
        }

        try:
            with mock.patch(
                "tlsfuzzer.analysis.stats.binomtest", binomtest_mock
            ):
                self.analysis.analyze_bit_sizes()
        except AttributeError:
            with mock.patch(
                "tlsfuzzer.analysis.stats.binom_test", binomtest_mock
            ):
                self.analysis.analyze_bit_sizes()

        binomtest_mock.assert_not_called()
        rel_t_test_mock.assert_not_called()
        wilcoxon_test_mock.assert_not_called()
        calc_values_mock.assert_called()

        self.analysis._k_sizes = None

    @mock.patch("tlsfuzzer.analysis.Analysis._figure_out_analysis_data_size")
    @mock.patch("tlsfuzzer.analysis.Analysis._calc_exact_values")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_plot_for_all_k")
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.wilcoxon_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.rel_t_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    @mock.patch("tlsfuzzer.analysis.Analysis.create_k_specific_dirs")
    @mock.patch("tlsfuzzer.analysis.shutil.rmtree")
    @mock.patch("builtins.open")
    def test_bit_size_measurement_analysis_main_100_samples(self, open_mock,
            rmtree_mock, dir_creation_mock, load_data_mock,
            rel_t_test_mock, wilcoxon_test_mock, interval_plot_mock,
            ecdf_plot_mock, scatter_plot_mock, worst_pair_mock,
            conf_plot_mock, calc_values_mock, figure_out_mock):

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            if "w" in mode:
                return mock.mock_open()(file_name, mode)

            if "timing.csv" in file_name:
                k_size = file_name.split("/")[-2]
                return mock.mock_open(
                    read_data= \
                        "256,{0}".format(k_size) +
                        ("\n0.5,0.4\n0.5,0.5\n0.4,0.5" * 20)
                )(file_name, mode)

            if "bootstrapped" in file_name:
                return mock.mock_open(
                    read_data= "1,0" + ("\n0.4" * 100) + ("\n0.6" * 100)
                )(file_name, mode)

            return mock.mock_open(
                read_data="0,256,3\n0,255,102\n0,254,103\n1,256,4\n" +
                          "1,254,104\n1,253,105"
            )(file_name, mode)

        k_sizes =  {
            256: 60,
            255: 100,
            254: 40,
            253: 20
        }

        self.analysis._k_sizes = k_sizes
        open_mock.side_effect = file_selector
        dir_creation_mock.return_value = k_sizes
        rel_t_test_mock.return_value = {(0, 1): 0.5}
        wilcoxon_test_mock.return_value = {(0, 1): 0.5}

        class dotDict(dict):
            __getattr__ = dict.__getitem__

        binomtest_result = {"statistic": 0.5, "pvalue": 0.5}
        binomtest_mock = mock.Mock()

        calc_values_mock.return_value = {
            "mean": 0.5, "median": 0.5, "trim_mean_05": 0.5,
            "trim_mean_25": 0.5, "trim_mean_45": 0.5, "trimean": 0.5
        }

        old_alpha = self.analysis.alpha
        self.analysis.alpha = 10

        try:
            with mock.patch(
                "tlsfuzzer.analysis.stats.binomtest", binomtest_mock
            ):
                binomtest_mock.return_value = dotDict(binomtest_result)
                ret_val = self.analysis.analyze_bit_sizes()
        except AttributeError:
            with mock.patch(
                "tlsfuzzer.analysis.stats.binom_test", binomtest_mock
            ):
                binomtest_mock.return_value = binomtest_result["pvalue"]
                ret_val = self.analysis.analyze_bit_sizes()

        self.analysis.alpha = old_alpha

        binomtest_mock.assert_called()
        rel_t_test_mock.assert_called()
        wilcoxon_test_mock.assert_called()
        calc_values_mock.assert_called()
        self.assertEqual(ret_val, 1)

        with mock.patch("builtins.print"):
            self.analysis.verbose = True
            old_bit_size_data_used = self.analysis._bit_size_data_used
            self.analysis._bit_size_data_used = 1000
            old_total_bit_size_data_used = self.analysis._bit_size_data_used

            try:
                with mock.patch(
                    "tlsfuzzer.analysis.stats.binomtest", binomtest_mock
                ):
                    binomtest_mock.return_value = dotDict(binomtest_result)
                    self.analysis.analyze_bit_sizes()
            except AttributeError:
                with mock.patch(
                    "tlsfuzzer.analysis.stats.binom_test", binomtest_mock
                ):
                    binomtest_mock.return_value = binomtest_result["pvalue"]
                    self.analysis.analyze_bit_sizes()

            self.analysis.verbose = False
            self.analysis._bit_size_data_used = old_bit_size_data_used
            self.analysis._bit_size_data_used = old_total_bit_size_data_used

        self.analysis._k_sizes = None

    @mock.patch("tlsfuzzer.analysis.Analysis._figure_out_analysis_data_size")
    @mock.patch("tlsfuzzer.analysis.Analysis._calc_exact_values")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_plot_for_all_k")
    @mock.patch("tlsfuzzer.analysis.Analysis.graph_worst_pair")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.wilcoxon_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.rel_t_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.load_data")
    @mock.patch("tlsfuzzer.analysis.Analysis.create_k_specific_dirs")
    @mock.patch("tlsfuzzer.analysis.shutil.rmtree")
    @mock.patch("builtins.open")
    @mock.patch("builtins.print")
    def test_bit_size_measurement_analysis_main_verbose(self, print_mock,
            open_mock, rmtree_mock, dir_creation_mock, load_data_mock,
            rel_t_test_mock, wilcoxon_test_mock, interval_plot_mock,
            ecdf_plot_mock, scatter_plot_mock, worst_pair_mock, conf_plot_mock,
            calc_values_mock, figure_out_mock):

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            if "w" in mode:
                return mock.mock_open()(file_name, mode)

            if "timing.csv" in file_name:
                k_size = file_name.split("/")[-2]
                return mock.mock_open(
                    read_data="256,{0}".format(k_size) +
                              ("\n0.5,0.4\n0.4,0.5" * 6)
                )(file_name, mode)

            return mock.mock_open(
                read_data="0,256,3\n0,255,102\n0,254,103\n1,256,4\n" +
                          "1,254,104\n1,253,105"
            )(file_name, mode)

        k_sizes =  {
            256: 1,
            255: 1,
            254: 2,
            253: 1
        }

        self.analysis._k_sizes = k_sizes
        open_mock.side_effect = file_selector
        dir_creation_mock.return_value = k_sizes
        rel_t_test_mock.return_value = {(0, 1): 0.5}
        wilcoxon_test_mock.return_value = {(0, 1): 0.5}

        class dotDict(dict):
            __getattr__ = dict.__getitem__

        binomtest_result = {"statistic": 0.5, "pvalue": 0.5}
        binomtest_mock = mock.Mock()

        calc_values_mock.return_value = {
            "mean": 0.5, "median": 0.5, "trim_mean_05": 0.5,
            "trim_mean_25": 0.5, "trim_mean_45": 0.5, "trimean": 0.5
        }

        self.analysis.verbose = True
        self.analysis.smart_bit_size_analysis = False

        try:
            with mock.patch(
                "tlsfuzzer.analysis.stats.binomtest", binomtest_mock
            ):
                binomtest_mock.return_value = dotDict(binomtest_result)
                self.analysis.analyze_bit_sizes()
        except AttributeError:
            with mock.patch(
                "tlsfuzzer.analysis.stats.binom_test", binomtest_mock
            ):
                binomtest_mock.return_value = binomtest_result["pvalue"]
                self.analysis.analyze_bit_sizes()

        self.analysis.verbose = False
        self.analysis.smart_bit_size_analysis = True

        binomtest_mock.assert_called()
        rel_t_test_mock.assert_called()
        wilcoxon_test_mock.assert_called()
        calc_values_mock.assert_called()

        self.analysis._k_sizes = None

    @mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure")
    @mock.patch("builtins.open")
    def test_bit_size_measurement_analysis_conf_plot(self, open_mock,
            print_figure_mock):

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            if "w" in mode:
                return mock.mock_open()(file_name, mode)

            if "bootstrapped" in file_name:
                k_size = file_name.split("/")[-2]
                return mock.mock_open(
                    read_data= \
                        "0,1" + ("\n0.5" * 20)
                )(file_name, mode)

            return mock.mock_open(
                read_data="0,256,3\n0,255,102\n0,254,103\n1,256,4\n" +
                          "1,254,104\n1,253,105"
            )(file_name, mode)

        open_mock.side_effect = file_selector

        self.analysis._k_sizes = {
            256: 200,
            255: 1000,
            254: 500,
            253: 250
        }
        self.analysis.conf_plot_for_all_k()
        self.analysis._k_sizes = None

        print_figure_mock.assert_called()

    @mock.patch("tlsfuzzer.analysis.os.makedirs")
    @mock.patch("builtins.open")
    def test_bit_size_measurement_analysis_create_k_dirs(self, open_mock,
        makedirs_mock):
        self.k_by_size = defaultdict(list)

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            if type(file_name) == int:
                return self.builtin_open(*args, **kwargs)

            if "k-by-size" in file_name:
                if "w" in mode:
                    r = mock.mock_open()(*args, **kwargs)
                    r.write.side_effect = lambda s: (
                        self.k_by_size[file_name].append(s)
                    )
                    return r
                else:
                    return mock.mock_open(
                        read_data = "".join(self.k_by_size[file_name])
                    )(*args, **kwargs)

            r = mock.mock_open(
                read_data="0,256,1\n0,255,102\n0,254,103\n0,256,2\n" +
                          "1,256,3\n1,254,104\n1,253,105"
            )(*args, **kwargs)
            r.tell.return_value = 1
            return r

        k_sizes = {
            256: 1,
            255: 1,
            254: 2,
            253: 1
        }

        self.analysis._k_sizes = k_sizes
        open_mock.side_effect = file_selector
        open_mock.return_value.tell.return_value = 0

        ret_value = self.analysis.create_k_specific_dirs()
        self.assertEqual(ret_value, k_sizes)

        self.k_by_size.clear()
        self.analysis.clock_frequency = 10000000
        ret_value = self.analysis.create_k_specific_dirs()
        self.assertEqual(ret_value, k_sizes)
        self.analysis.clock_frequency = None

        with mock.patch("builtins.print"):
            self.k_by_size.clear()
            self.analysis.verbose = True
            ret_value = self.analysis.create_k_specific_dirs()
            self.analysis.verbose = False

        self.k_by_size.clear()
        sanity_k_sizes = k_sizes.copy()
        del sanity_k_sizes[256]
        self.analysis._k_sizes = sanity_k_sizes
        self.analysis.skip_sanity = True
        ret_value = self.analysis.create_k_specific_dirs()
        self.analysis.skip_sanity = False
        self.assertEqual(ret_value, sanity_k_sizes)

        self.analysis._k_sizes = None

    @mock.patch("builtins.open")
    def test_check_data_for_zero_all_zeros(self, open_mock):

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            return mock.mock_open(
                read_data= "0.05,0.05\n" * 20
            )(file_name, mode)

        open_mock.side_effect = file_selector

        ret_value = self.analysis._check_data_for_zero()

        self.assertEqual(ret_value, False)

    @mock.patch("builtins.open")
    def test_check_data_for_zero_two_non_zero(self, open_mock):

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            return mock.mock_open(
                read_data= ("0.05,0.05\n" * 20) + ("0.04,0.05\n" * 2)
            )(file_name, mode)

        open_mock.side_effect = file_selector

        ret_value = self.analysis._check_data_for_zero()

        self.assertEqual(ret_value, False)

    @mock.patch("builtins.open")
    def test_check_data_for_zero_five_non_zero(self, open_mock):

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            return mock.mock_open(
                read_data= ("0.05,0.05\n" * 20) + ("0.04,0.05\n" * 5)
            )(file_name, mode)

        open_mock.side_effect = file_selector

        ret_value = self.analysis._check_data_for_zero()

        self.assertEqual(ret_value, True)

    @unittest.skipIf(sys.version_info[0] == 3 and sys.version_info[1] == 6,
                 "The test is not relevant to python 3.6")
    @mock.patch("tlsfuzzer.analysis.np.memmap")
    @mock.patch("builtins.open")
    def test_long_format_to_binary(self, open_mock,
        memmap_mock):

        def file_selector(*args, **kwargs):
            file_name = args[0]
            try:
                mode = args[1]
            except IndexError:
                mode = "r"

            if "w" in mode:
                return mock.mock_open()(file_name, mode)

            return mock.mock_open(
                read_data= ("0,256,1\n0,255,102\n0,254,103\n0,256,2\n" +
                           "1,256,3\n1,254,104\n1,253,105\n" *
                           (1024 * 1024 * 4))
            )(file_name, mode)

        open_mock.side_effect = file_selector

        self.analysis._long_format_to_binary(
            "measurements.csv",
            "measurements.bin"
        )

    @mock.patch("builtins.print")
    @mock.patch("tlsfuzzer.analysis.np.memmap")
    def test_bit_size_skillings_mack_test(self,
            memmap_mock, print_mock):

        memmap_mock.return_value = {
            "block": self.blocks, "group": self.groups, "value": self.values
        }

        self.analysis.skillings_mack_test("measurements.bin")

        memmap_mock.assert_called_once()

        self.analysis.verbose = True
        self.analysis.skillings_mack_test("measurements.bin")
        self.analysis.verbose = False

    def test_bit_size_come_to_verdict(self):
        tests = [
            (0.5, 1, 1, 1, "VULNERABLE"),
            (1e-10, 1, 0, 1, "VULNERABLE"),
            (1e-6, 1, 0, 1, "suggesting"),
            (0.5, 1e-11, 0, 0, "verified"),
            (0.5, 5e-10, 0, 0, "most likely"),
            (0.5, 1e-3, 0, 1, "Large confidence intervals detected"),
            (0.5, 1, 0, 1, "Very large confidence intervals detected"),
        ]

        values = [0, 1e-13]
        bit_size_bootstraping = {
            255: {
                "trim_mean_05": values,
                "trim_mean_45": values
            },
            254: {
                "trim_mean_05": values,
                "trim_mean_45": values
            },
            253: {
                "trim_mean_05": values,
                "trim_mean_45": values
            }
        }

        for test in tests:
            bit_size_bootstraping[255]["trim_mean_05"][1] = test[1]
            self.analysis._bit_size_bootstraping = bit_size_bootstraping

            difference, verdict = \
                self.analysis._bit_size_come_to_verdict(test[2], test[0])
            self.assertEqual(test[3], difference)
            self.assertIn(test[4], verdict)

        # Final test with no k-sizes in it
        self.analysis._bit_size_bootstraping = {}
        difference, verdict = \
            self.analysis._bit_size_come_to_verdict(0, 1)
        self.assertEqual(2, difference)
        self.assertIn("Not enough", verdict)

        self.analysis._bit_size_bootstraping = None

    @mock.patch("builtins.open")
    def test_bit_size_write_summary(self, open_mock):
        _summary = []

        def file_selector(*args, **kwargs):
            r = mock.mock_open()(*args, **kwargs)
            r.write.side_effect = lambda s: (
                _summary.extend(s.split('\n'))
            )
            return r

        self.analysis._k_sizes = {
            256: 100,
            255: 1000,
            254: 500,
            253: 500
        }

        open_mock.side_effect = file_selector

        values_pos = [0,5, 1e-9]
        values_neg = [-0.5, 1e-9]
        self.analysis._bit_size_bootstraping = {
            255: {
                "trim_mean_05": values_pos,
                "trim_mean_45": values_neg
            },
            254: {
                "trim_mean_05": values_neg,
                "trim_mean_45": values_pos
            },
            253: {
                "trim_mean_05": values_pos,
                "trim_mean_45": values_neg
            }
        }
        self.analysis._bit_size_sign_test = {255: 0.3, 254: 0.7, 253: 0.4}
        self.analysis._bit_size_wilcoxon_test = {255: 0.2, 254: 0.8, 253: 0.6}
        self.analysis._total_bit_size_data_used = 1500

        self.analysis._bit_size_write_summary("passed", 0.5)

        self.assertEqual(
            _summary[2], "Skilling-Mack test p-value: 5.000000e-01"
        )
        self.assertEqual(
            _summary[3],
            "Sign test p-values (min, average, max): " +
            "3.00e-01, 4.67e-01, 7.00e-01"
        )
        self.assertEqual(
            _summary[4],
            "Wilcoxon test p-values (min, average, max): " +
            "2.00e-01, 5.33e-01, 8.00e-01"
        )
        self.assertEqual(
            _summary[5],
            "Used 1,500 (75.00%) out of 2,000 available " +
            "data observations for results."
        )
        self.assertEqual(_summary[6], "passed")

        self.analysis._k_sizes = None

    @mock.patch("tlsfuzzer.analysis.np.memmap")
    @mock.patch("tlsfuzzer.analysis.Analysis.calc_diff_conf_int")
    @mock.patch("builtins.print")
    def test_figure_out_analysis_data_size(self, print_mock,
            calc_diff_conf_int_mock, mock_memmap):

        mock_memmap.return_value = {
            'tuple_num': [0, 0, 0, 0, 1, 1, 1],
            'k_size': [256, 255, 254, 256, 256, 254, 253],
            'value': [1, 102, 103, 2, 3, 104, 105]
        }

        def custom_calc_conf_int(pair):
            self.analysis._bit_size_data_used = 1000
            if self._all_cis_zeros:
                return {
                    'mean': (0, 0, 0),
                    'median': (0, 0, 0),
                    'trim_mean_05': (0, 0, 0),
                    'trim_mean_25': (0, 0, 0),
                    'trim_mean_45': (0, 0, 0),
                    'trimean': (0, 0, 0)
                }
            else:
                return {
                    'mean': (-5.0e-07, -9.9e-08, 2.5e-07),
                    'median': (-8.0e-08, -3.8e-08, 1.1e-08),
                    'trim_mean_05': (-1.6e-07, 1.5e-08, 2.1e-07),
                    'trim_mean_25': (-6.9e-08, -2.4e-08, 2.5e-08),
                    'trim_mean_45': (-7.9e-08, -3.5e-08, 1.3e-08),
                    'trimean': (-7.9e-08, -2.2e-08, 3.86e-08)
                }

        calc_diff_conf_int_mock.side_effect = custom_calc_conf_int

        self.analysis._k_sizes = {
            256: 2,
            255: 1,
            254: 2,
            253: 1
        }
        old_bit_recall_size = self.analysis.bit_recognition_size

        self._all_cis_zeros = True
        self.analysis._bit_size_data_limit = 10000
        self.analysis.bit_recognition_size = 1
        self.analysis._figure_out_analysis_data_size()
        print_mock.assert_called_once_with(
            "[W] There is not enough data on recognition size to " +
            "calculate desired sample size. Using all available samples."
        )

        self._all_cis_zeros = False
        for size in [1, 2, 3, 30, 4]:
            self.analysis.verbose = not (size == 30)
            self.analysis._bit_size_data_limit = 10000
            self.analysis.bit_recognition_size = size
            self.analysis._figure_out_analysis_data_size()
            self.assertEqual(self.analysis._bit_size_data_limit, 9109100)

        # restore of changed variables
        self._bit_size_data_limit = 10000
        self.analysis.bit_recognition_size = old_bit_recall_size
        self.analysis._k_sizes = None

        self.assertEqual(self.analysis.output, "/tmp")

    @mock.patch("tlsfuzzer.analysis.os.path.getsize")
    @mock.patch("tlsfuzzer.analysis.np.memmap")
    def test_k_sizes_totals(self, mock_memmap, mock_getsize):
        k_sizes = [256, 255, 254, 256, 256, 254, 253]
        mock_memmap.return_value = {'k_size': k_sizes}
        mock_getsize.return_value = len(k_sizes) * 18

        self.analysis._k_sizes_totals("measurements.bin")

        self.assertEqual(self.analysis._k_sizes, {
            256: 3, 255: 1, 254: 2, 253: 1
        })

        with mock.patch("builtins.print") as mock_print:
            self.analysis.verbose = True
            self.analysis._k_sizes_totals("measurements.bin")
            self.analysis.verbose = False
            self.assertIn(
                mock.call("[i] Max K size detected: 256"), mock_print.mock_calls
            )
            self.assertIn(
                mock.call("[i] Min K size detected: 253"), mock_print.mock_calls
            )

        self.analysis._k_sizes = None

    @mock.patch("tlsfuzzer.analysis.np.memmap")
    @mock.patch("tlsfuzzer.analysis.os.makedirs")
    def test_thread_workers(self, mock_makedirs, mock_memmap):

        mock_memmap.return_value = {
            'tuple_num': [0, 0, 0, 0, 1, 1, 1],
            'k_size': [256, 255, 254, 256, 256, 254, 253],
            'value': [1, 102, 103, 2, 3, 104, 105]
        }

        # Testing _k_sizes_totals_worker
        args = ("measurements.bin", (1, 6))
        results = self.analysis._k_sizes_totals_worker(args)
        self.assertEqual(dict(results), { 256: 2, 255: 1, 254: 2 })

        # Testing _bit_size_smart_analysis_worker
        args = ("measurements.bin", (0, 20))
        self.analysis._bit_size_data_limit = 3
        self.analysis._k_sizes = { 256: 6, 255: 3, 254: 1, 253: 1}
        results = self.analysis._bit_size_smart_analysis_worker(args)
        self.assertGreater(len(results), 0)
        self.analysis._bit_size_data_limit = None
        self.analysis._k_sizes = None

        # Testing _k_specific_writing_worker
        def file_selector(*args, **kwargs):
            return mock.mock_open()(*args, **kwargs)

        class mock_pipe:
            def __init__(self):
                self.recv_counter = 0
                self.values = []

            def recv(self):
                self.recv_counter += 1

                if self.recv_counter == 1:
                    self.values = [(1, 101), (2, 102), (3, 103)]
                elif self.recv_counter == 2:
                    self.values = [(4, 204), (5, 205), (6, 206)]
                else:
                    return None

                return self

            def __getitem__(self, pos):
                return self

            def close(self):
                pass

        with mock.patch("builtins.open") as mock_open:
            mock_open.side_effect = file_selector
            args = ("/tmp/", mock_pipe(), 255, 256, 1)
            results = self.analysis._k_specific_writing_worker(args)
            self.assertEqual(results[0], 255)
            self.assertGreater(results[1], 0)

@unittest.skipIf(failed_import,
                 "Could not import analysis. Skipping related tests.")
class TestHammingAnalysis(unittest.TestCase):

    @mock.patch("builtins.print")
    def test_hamming_analysis_negative(self, mock_print):
        with tempfile.TemporaryDirectory() as tmpdirname:
            with open(os.path.join(tmpdirname, "measurements.csv"), "w") \
                    as data:
                for tuple_num in range(100):
                    groups = sorted(list(set(
                        np.random.binomial(256, 0.5, 20)
                    )))
                    values = np.random.normal(1e-3, 1e-10, size=len(groups))

                    for i, j in zip(groups, values):
                        data.write("{0},{1},{2}\n".format(tuple_num, i, j))

            analysis = Analysis(
                tmpdirname, verbose=True, draw_conf_interval_plot=False,
                bit_size_analysis=True, run_wilcoxon_test=False,
                run_t_test=False, run_sign_test=False, draw_ecdf_plot=False
            )

            ret = analysis.analyse_hamming_weights()

            self.assertLess(1e-6, analysis.skillings_mack_test(
                os.path.join(tmpdirname, "measurements.bin")))

        self.assertEqual(ret, 0)

        self.assertIn(
            mock.call(
                '[i] Sample large enough to detect 1 ns difference: True'),
            mock_print.mock_calls
        )
        for i in mock_print.mock_calls:
            if "Skillings-Mack test p-value" in str(i):
                break
        else:
            self.assertFalse(True)

    @mock.patch("builtins.print")
    def test_hamming_analysis_positive(self, mock_print):
        with tempfile.TemporaryDirectory() as tmpdirname:
            with open(os.path.join(tmpdirname, "measurements.csv"), "w") \
                    as data:
                for tuple_num in range(100):
                    groups = sorted(list(set(
                        np.random.binomial(256, 0.5, 20)
                    )))
                    values = [
                        np.random.normal(1e-3, 1e-10) + i * 1e-9
                        for i in groups
                    ]

                    for i, j in zip(groups, values):
                        data.write("{0},{1},{2}\n".format(tuple_num, i, j))

            analysis = Analysis(
                tmpdirname, verbose=True, draw_conf_interval_plot=False,
                bit_size_analysis=True, run_wilcoxon_test=False,
                run_t_test=False, run_sign_test=False, draw_ecdf_plot=False
            )

            ret = analysis.analyse_hamming_weights()

            self.assertGreater(1e-6, analysis.skillings_mack_test(
                os.path.join(tmpdirname, "measurements.bin")))

        self.assertEqual(ret, 1)

        self.assertNotIn(
            mock.call(
                '[i] Sample large enough to detect 1 ns difference: True'),
            mock_print.mock_calls
        )
        self.assertNotIn(
            mock.call(
                '[i] Sample large enough to detect 1 ns difference: False'),
            mock_print.mock_calls
        )
        for i in mock_print.mock_calls:
            if "Skillings-Mack test p-value" in str(i):
                break
        else:
            self.assertFalse(True)

    @mock.patch("tlsfuzzer.analysis.Figure")
    @mock.patch("tlsfuzzer.analysis.FigureCanvas")
    @mock.patch("builtins.print")
    @mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot")
    @mock.patch("tlsfuzzer.analysis.Analysis.sign_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.wilcoxon_test")
    @mock.patch("tlsfuzzer.analysis.Analysis.rel_t_test")
    def test_hamming_analysis_quick(
            self, mock_t_test, mock_wilcoxon_test, mock_sign_test,
            mock_ecdf_plot,
            mock_print,
            mock_figure_canvas, mock_figure
        ):

        with tempfile.TemporaryDirectory() as tmpdirname:
            with open(os.path.join(tmpdirname, "measurements.csv"), "w") \
                    as data:
                for tuple_num in range(1000):
                    groups = sorted(list(set(
                        np.random.binomial(10, 0.5, 5)
                    )))
                    values = np.random.normal(1e-3, 1e-10, size=len(groups))

                    for i, j in zip(groups, values):
                        data.write("{0},{1},{2}\n".format(tuple_num, i, j))

            analysis = Analysis(
                tmpdirname, verbose=True,
                workers=1, # limit workers as process startup is expensive
                bit_size_analysis=True,
            )

            old_bootstrap = analysis._bootstrap_differences
            analysis._bootstrap_differences = lambda pair, reps, status: \
                old_bootstrap(pair, 4, status)

            ret = analysis.analyse_hamming_weights()

            self.assertLess(1e-6, analysis.skillings_mack_test(
                os.path.join(tmpdirname, "measurements.bin")))

        self.assertEqual(ret, 0)

        self.assertIn(
            mock.call(
                '[i] Sample large enough to detect 1 ns difference: True'),
            mock_print.mock_calls
        )
        for i in mock_print.mock_calls:
            if "Skillings-Mack test p-value" in str(i):
                break
        else:
            self.assertFalse(True)

    def test_hamming_analysis_not_verbose(self):
        with tempfile.TemporaryDirectory() as tmpdirname:
            with open(os.path.join(tmpdirname, "measurements.csv"), "w") \
                    as data:
                for tuple_num in range(100):
                    groups = sorted(list(set(
                        np.random.binomial(256, 0.5, 20)
                    )))
                    values = np.random.normal(1e-3, 1e-10, size=len(groups))

                    for i, j in zip(groups, values):
                        data.write("{0},{1},{2}\n".format(tuple_num, i, j))

            analysis = Analysis(
                tmpdirname, verbose=False, draw_conf_interval_plot=False,
                bit_size_analysis=True, run_wilcoxon_test=False,
                run_t_test=False, run_sign_test=True, draw_ecdf_plot=False
            )

            ret = analysis.analyse_hamming_weights()

            self.assertLess(1e-6, analysis.skillings_mack_test(
                os.path.join(tmpdirname, "measurements.bin")))

        self.assertEqual(ret, 0)