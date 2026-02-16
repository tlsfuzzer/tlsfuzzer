from __future__ import print_function
import os
import shutil
import tempfile
from io import open

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
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_main_error_on_output_collision(self):
        """
        Test 1: Error should occur if the output filename
        matches one of the input filenames.
        """
        file_a = os.path.join(self.test_dir, "input1.bin")
        file_b = os.path.join(self.test_dir, "input2.bin")

        with open(file_a, "wb") as f:
            f.write(b"content_a")
        with open(file_b, "wb") as f:
            f.write(b"content_b")

        # Mock sys.argv to simulate CLI input
        args = ["shuffled_keys_generator.py", "-o", file_a, file_a, file_b]

        with mock.patch("sys.argv", args):
            with self.assertRaises(SystemExit):
                main()

    def test_main_concatenation_logic(self):
        """
        Test 2: Check concatenation based on log.csv ordering.
        """
        file_a = os.path.join(self.test_dir, "A.bin")
        file_b = os.path.join(self.test_dir, "B.bin")
        out_file = os.path.join(self.test_dir, "output.bin")
        log_file = os.path.join(self.test_dir, "log.csv")

        content_a = b"AAAAA"
        content_b = b"BBBBB"

        with open(file_a, "wb") as f:
            f.write(content_a)
        with open(file_b, "wb") as f:
            f.write(content_b)

        # Mock sys.argv for the success case
        args = [
            "shuffled_keys_generator.py",
            "-n", "1",
            "-o", out_file,
            "--log", log_file,
            file_a,
            file_b
        ]

        with mock.patch("sys.argv", args):
            main()

        # Read log.csv to see which permutation was chosen
        with open(log_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            order = lines[1].strip()

        with open(out_file, "rb") as f:
            result_content = f.read()

        # Validate result against the logged permutation
        if order == "0,1":
            self.assertEqual(result_content, content_a + content_b)
        elif order == "1,0":
            self.assertEqual(result_content, content_b + content_a)
        else:
            self.fail("Unexpected order '{0}' found in log.csv".format(order))

if __name__ == "__main__":
    unittest.main()
