from __future__ import print_function, with_statement
import os
import io
import sys

try:
    import unittest2 as unittest
except ImportError:
    import unittest

try:
    import mock
except ImportError:
    import unittest.mock as mock

from tlsfuzzer._apps.shuffled_keys_generator import main

class TestShuffledKeysGenerator(unittest.TestCase):
    @unittest.skipIf(sys.version_info < (2, 7),
                 "mock_open doesn't work correctly in mock v2.0.0")
    def test_main_error_on_output_collision(self):
        """
        Test 1: Error should occur if the output filename matches input.
        """
        file_a = "input1.bin"
        file_b = "input2.bin"

        def open_side_effect(name, *args, **kwargs):
            return io.StringIO(u"dummy content")

        # Patching locations
        path_app = "tlsfuzzer._apps.shuffled_keys_generator.open"
        path_log = "tlsfuzzer.utils.log.open"

        # Nested 'with' blocks for Python 2.6 compatibility
        with mock.patch(path_app, side_effect=open_side_effect):
            with mock.patch(path_log, side_effect=open_side_effect, create=True):
                with mock.patch("os.path.exists", return_value=True):
                    args = ["shuffled_keys_generator.py", "-o", file_a, file_a, file_b]
                    with mock.patch("sys.argv", args):
                        with self.assertRaises(SystemExit):
                            main()

    @unittest.skipIf(sys.version_info < (2, 7),
                 "mock_open doesn't work correctly in mock v2.0.0")
    def test_main_concatenation_logic(self):
        """
        Test 2: Check concatenation based on log.csv ordering across Py2 and Py3.
        """
        # 1. Groomed Data Definitions
        raw_data = {
            "A.bin": u"AAAAA",
            "B.bin": u"BBBBB"
        }
        # Pre-calculate expected byte results for the final assertion
        expected_bytes = dict((k, v.encode('utf-8')) for k, v in raw_data.items())

        # CROSS-VERSION BUFFER SELECTION
        # Python 2.7 csv module requires bytes; Python 3.x requires text
        if sys.version_info[0] < 3:
            log_storage = io.BytesIO()
        else:
            log_storage = io.StringIO()
        out_storage = io.BytesIO()

        # Prevent context managers from closing the memory buffers
        log_storage.close = lambda: None
        out_storage.close = lambda: None

        def open_side_effect(name, mode='r', **kwargs):
            if "log.csv" in name:
                if 'r' in mode:
                    log_storage.seek(0)
                return log_storage

            if "output.bin" in name:
                return out_storage

            # Dynamic lookup for input files
            for filename, content in raw_data.items():
                if filename in name:
                    return io.StringIO(content)

            return io.StringIO(u"")

        # 2. Execution with Mocks
        path_app = "tlsfuzzer._apps.shuffled_keys_generator.open"
        path_log = "tlsfuzzer.utils.log.open"

        with mock.patch(path_app, side_effect=open_side_effect):
            with mock.patch(path_log, side_effect=open_side_effect, create=True):
                with mock.patch("os.path.exists", return_value=True):
                    args = [
                        "shuffled_keys_generator.py",
                        "-n", "1",
                        "-o", "output.bin",
                        "--log", "log.csv",
                        "A.bin", "B.bin"
                    ]
                    with mock.patch("sys.argv", args):
                        main()

        # 3. Validation
        # Handle the difference in getvalue() return types (bytes vs str)
        log_raw = log_storage.getvalue()
        if isinstance(log_raw, bytes):
            log_contents = log_raw.decode('utf-8')
        else:
            log_contents = log_raw

        lines = log_contents.strip().split('\n')
        if len(lines) < 2:
            self.fail("log.csv missing data. Content: {0}".format(log_contents))

        order = lines[1].strip()
        result_content = out_storage.getvalue()

        # Validate result against the logged permutation
        if order == "0,1":
            self.assertEqual(result_content, expected_bytes["A.bin"] + expected_bytes["B.bin"])
        elif order == "1,0":
            self.assertEqual(result_content, expected_bytes["B.bin"] + expected_bytes["A.bin"])
        else:
            self.fail("Unexpected order '{0}' found in log.csv".format(order))

if __name__ == "__main__":
    unittest.main()
