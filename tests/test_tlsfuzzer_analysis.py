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

import sys

failed_import = False
try:
    from tlsfuzzer.analysis import Analysis, main, TestPair, help_msg
    import pandas as pd
    import numpy as np
except ImportError:
    failed_import = True


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
            'B': [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        })
        self.neq_data_overlap = pd.DataFrame(data={
            'A': [0, 0, 1, 7, 7] + [7] * 95,
            'B': [0, 0, 2, 6, 7] + [7] * 95,
        })
        timings = pd.DataFrame(data=data)
        self.mock_read_csv = mock.Mock()
        self.mock_read_csv.return_value = timings

    def test_report(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot") as mock_diff_ecdf:
                    with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                        with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                            with mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot"):
                                with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                                    with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                        with mock.patch("builtins.print"):
                                            with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                                analysis = Analysis("/tmp")
                                                ret = analysis.generate_report()

                                                self.mock_read_csv.assert_called()
                                                #mock_ecdf.assert_called_once()
                                                #mock_box.assert_called_once()
                                                #mock_scatter.assert_called_once()
                                                # we're writing to report.csv, legend.csv,
                                                # sample_stats.csv, and report.txt
                                                self.assertEqual(mock_open.call_count, 4)
                                                self.assertEqual(ret, 0)

    def test_report_multithreaded(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                    with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                        with mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot"):
                            with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                                with mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot"):
                                    with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                        with mock.patch("builtins.print"):
                                            with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                                analysis = Analysis("/tmp",
                                                    multithreaded_graph=True)
                                                ret = analysis.generate_report()

                                                self.mock_read_csv.assert_called()
                                                #mock_ecdf.assert_called_once()
                                                #mock_box.assert_called_once()
                                                #mock_scatter.assert_called_once()
                                                # we're writing to report.csv, legend.csv,
                                                # sample_stats.csv, and report.txt
                                                self.assertEqual(mock_open.call_count, 4)
                                                self.assertEqual(ret, 0)

    def test_report_neq(self):
        timings = pd.DataFrame(data=self.neq_data)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.diff_ecdf_plot") as mock_diff_ecdf:
                    with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                        with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                            with mock.patch("tlsfuzzer.analysis.Analysis.diff_scatter_plot"):
                                with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                                    with mock.patch("tlsfuzzer.analysis.Analysis.friedman_test") as mock_friedman:
                                        with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                            with mock.patch("builtins.print"):
                                                mock_friedman.return_value = 0
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

    def test_report_error_in_box_plot(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                    with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                        with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                            with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                with mock.patch("builtins.print"):
                                    with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                        mock_box.side_effect = Exception("Test")
                                        analysis = Analysis("/tmp")

                                        with self.assertRaises(Exception) as exc:
                                            ret = analysis.generate_report()

                                        self.assertIn("Box plot graph", str(exc.exception))

    def test_report_error_in_scatter_plot(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                    with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                        with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                            with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                with mock.patch("builtins.print"):
                                    with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                        mock_scatter.side_effect = Exception("Test")
                                        analysis = Analysis("/tmp")

                                        with self.assertRaises(Exception) as exc:
                                            ret = analysis.generate_report()

                                        self.assertIn("Scatter plot graph", str(exc.exception))

    def test_report_error_in_ecdf_plot(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                    with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                        with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                            with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                with mock.patch("builtins.print"):
                                    with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                        mock_ecdf.side_effect = Exception("Test")
                                        analysis = Analysis("/tmp")

                                        with self.assertRaises(Exception) as exc:
                                            ret = analysis.generate_report()

                                        self.assertIn("ECDF graph", str(exc.exception))

    def test_report_error_in_conf_interval_plot(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                    with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                        with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                            with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                with mock.patch("builtins.print"):
                                    with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                        mock_conf_int.side_effect = Exception("Test")
                                        analysis = Analysis("/tmp")

                                        with self.assertRaises(Exception) as exc:
                                            ret = analysis.generate_report()

                                        self.assertIn("Conf interval graph", str(exc.exception))

    def test_report_error_in_MT_box_plot(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                    with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                        with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                            with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                with mock.patch("builtins.print"):
                                    with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                        mock_box.side_effect = Exception("Test")
                                        analysis = Analysis("/tmp", multithreaded_graph=True)

                                        with self.assertRaises(Exception) as exc:
                                            ret = analysis.generate_report()

                                        self.assertIn("Box plot graph", str(exc.exception))

    def test_report_error_in_MT_scatter_plot(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                    with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                        with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                            with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                with mock.patch("builtins.print"):
                                    with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                        mock_scatter.side_effect = Exception("Test")
                                        analysis = Analysis("/tmp", multithreaded_graph=True)

                                        with self.assertRaises(Exception) as exc:
                                            ret = analysis.generate_report()

                                        self.assertIn("Scatter plot graph", str(exc.exception))

    def test_report_error_in_MT_ecdf_plot(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                    with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                        with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                            with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                with mock.patch("builtins.print"):
                                    with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                        mock_ecdf.side_effect = Exception("Test")
                                        analysis = Analysis("/tmp", multithreaded_graph=True)

                                        with self.assertRaises(Exception) as exc:
                                            ret = analysis.generate_report()

                                        self.assertIn("ECDF graph", str(exc.exception))

    def test_report_error_in_MT_conf_interval_plot(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
            with mock.patch("tlsfuzzer.analysis.Analysis.ecdf_plot") as mock_ecdf:
                with mock.patch("tlsfuzzer.analysis.Analysis.box_plot") as mock_box:
                    with mock.patch("tlsfuzzer.analysis.Analysis.scatter_plot") as mock_scatter:
                        with mock.patch("tlsfuzzer.analysis.Analysis.conf_interval_plot") as mock_conf_int:
                            with mock.patch("__main__.__builtins__.open", mock.mock_open()) as mock_open:
                                with mock.patch("builtins.print"):
                                    with mock.patch("tlsfuzzer.analysis.Analysis._convert_to_binary"):
                                        mock_conf_int.side_effect = Exception("Test")
                                        analysis = Analysis("/tmp", multithreaded_graph=True)

                                        with self.assertRaises(Exception) as exc:
                                            ret = analysis.generate_report()

                                        self.assertIn("Conf interval graph", str(exc.exception))

    def test_wilcoxon_test(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
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
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
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
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
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
            self.assertEqual(len(res), 1)
            for index, result in res.items():
                self.assertLessEqual(result, 0.001)

    def test_sign_test_with_alternative_greater_and_neq_data(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data") as load_data:
            load_data.return_value = self.neq_data
            analysis = Analysis("/tmp")

            res = analysis.sign_test(alternative="greater")
            self.assertEqual(len(res), 1)
            for index, result in res.items():
                self.assertLessEqual(result, 1)

    def test_rel_t_test(self):
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", self.mock_read_csv):
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

    def test_box_test_neq(self):
        timings = pd.DataFrame(data=self.neq_data)
        mock_read_csv = mock.Mock()
        mock_read_csv.return_value = timings
        with mock.patch("tlsfuzzer.analysis.Analysis.load_data", mock_read_csv):
            analysis = Analysis("/tmp")

            res = analysis.box_test()
            self.assertEqual(len(res), 1)
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

    def test_ecdf_plot(self):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            self.analysis.ecdf_plot()
            self.assertEqual(mock_save.call_args_list,
                [mock.call('/tmp/ecdf_plot.png', bbox_inches='tight'),
                 mock.call('/tmp/ecdf_plot_zoom_in.png', bbox_inches='tight')])

    def test_diff_ecdf_plot(self):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            self.analysis.diff_ecdf_plot()
            self.assertEqual(mock_save.call_args_list,
                [mock.call('/tmp/diff_ecdf_plot.png', bbox_inches='tight'),
                 mock.call('/tmp/diff_ecdf_plot_zoom_in_98.png',
                            bbox_inches='tight'),
                 mock.call('/tmp/diff_ecdf_plot_zoom_in_33.png',
                            bbox_inches='tight'),
                 mock.call('/tmp/diff_ecdf_plot_zoom_in_10.png',
                            bbox_inches='tight')])

    def test_scatter_plot(self):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            self.analysis.scatter_plot()
            self.assertEqual(mock_save.call_args_list,
                [mock.call('/tmp/scatter_plot.png', bbox_inches='tight'),
                 mock.call('/tmp/scatter_plot_zoom_in.png',
                           bbox_inches='tight')])

    def test_diff_scatter_plot(self):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            self.analysis.diff_scatter_plot()
            self.assertEqual(mock_save.call_args_list,
                [mock.call('/tmp/diff_scatter_plot.png', bbox_inches='tight'),
                 mock.call('/tmp/diff_scatter_plot_zoom_in.png',
                           bbox_inches='tight')])

    def test_box_plot(self):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            with mock.patch("tlsfuzzer.analysis.Analysis._calc_percentiles")\
                    as mock_percentiles:
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

    def test_conf_interval_plot(self):
        with mock.patch("tlsfuzzer.analysis.FigureCanvas.print_figure",
                        mock.Mock()) as mock_save:
            with mock.patch("__main__.__builtins__.open", mock.mock_open())\
                    as mock_open:
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
                     mock.call('/tmp/conf_interval_plot_trimean.png',
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
                    mock_init.assert_called_once_with(output, True, True,
                                                      True, False)

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
                    mock_init.assert_called_once_with(output, True, True,
                                                      True, True)

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
                        output, False, False, False, False)

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

        a._convert_to_binary()
