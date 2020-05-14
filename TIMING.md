Collecting timing information in `tlsfuzzer`
===========================================

This document describes how to write tests scenarios that collect timing
information for later analysis. The timing runner repeatedly runs tests with
tcpdump in the background. The timing information is only ever extracted from
the latency of last server response in each conversation. Timing analysis
requires additional dependencies. You can install them by running this command
in the root of the repository.

```bash
pip install -r requirements-timing.txt
```

Test argument interface
-----------------------

Any test that will be collecting timing information need provide the following
argument interface. Specifying the network interface that packet capture should
listen on should be enough to time the tests.

| Argument      | Required | Description  |
|:-------------|:--------:|:------------ |
| `-i interface`| Yes      | Interface to run tcpdump on       |
| `-o dir`      | No       | Output directory (default `/tmp`) |
| `--repeat rep`| No       | Repeat each test `rep` times (default 100) |

Test structure
--------------

After processing these arguments, one would proceed to write the test as usual,
probably adding a `sanity` test case and tests cases relating to the feature
under test. The example script `test-conversation.py` can be used as a starting
point.

After it is clear, that all the tests passed, timing of the tests can be executed.
Start by importing the `TimingRunner` class.
Because the timing information collection adds some extra dependencies, it is
necessary to wrap everything related to timing in an if statement:

```python
if TimingRunner.check_tcpdump():
```

Now, the the `TimingRunner` class can be initialized with the name of
the currently run test, list of conversations
(`sampled_tests` in the reference script),
output directory (the `-o` argument), TLS server host and port, and finally the
network interface from the `-i` argument.

Next step is to generate log with random order of test cases for each run. This
is done by calling the function `generate_log()` from the `TimingRunner`
instance. This function takes the familiar `run_only` and `run_exclude`
variables that can filter what tests should be run. Note that this function
will exclude any tests named "sanity". The last argument to this function is
how many times each test should be run (`--repeat` argument).
The log is saved in the output directory.

The last step is to call `run()` function
from the `TiminingRunner` instance in order to launch tcpdump and begin iterating
over the tests.Provided you were able to install the timing dependencies,
this will also launch analysis that will process the packet capture and output
the timing information associated with the test class into a csv file.

Executing the test and analysis
-------------------------------

Tests can be executed the same way as any non-timing tests, just make sure the
current user has permissions to run tcpdump or use sudo. As an example, the
Bleichenbacher test is extended to use the timing functionality:

```bash
sudo PYTHONPATH=. python scripts/test-bleichenbacher-workaround.py -i lo
```

By default, if all dependencies are available, the analysis will run right
after the timing packet capture.  
In case you want to run the analysis on another machine (e.g. you were not able
to install the requirements) you can do this by providing the log, the packet
capture and server port and hostname (or ip) to the analysis script.

```bash
sudo PYTHONPATH=. python tlsfuzzer/analysis.py -h localhost -p 4433 -c capture.pcap -l class.log -o timing.csv
```
