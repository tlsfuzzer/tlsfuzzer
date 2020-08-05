===============
Timing analysis
===============

As cryptographic implementations process secret data, they need to ensure
that side effects of processing that data do not reveal information about
the secret data.

When an implementation takes different amounts of time to process the messages
we consider it a timing side-channel. When such side-channels reflect the
contents of the processed messages we call them timing oracles.

One of the oldest timing oracles is the attack described by Daniel
Bleichenbacher against RSA key exchange. You can test for it using the
`test-bleichenbacher-timing.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-bleichenbacher-timing.py>`_
script.

The other is related to de-padding and verifying MAC values in CBC ciphertexts,
the newest iteration of which is called Lucky Thirteen. You can test for it
using the
`test-lucky13.py
<https://github.com/tomato42/tlsfuzzer/blob/master/scripts/test-lucky13.py>`_
script.

Environment setup
=================

As the scripts measure the time it takes a server to reply to a message,
a server running alone on a machine, with no interruptions from other
services or processes will provide statistically significant results with
fewest observations.

Hardware selection
------------------

You will want a server with at least 3 physical cores: one to run
the OS, tlsfuzzer script, etc., one to run the tcpdump process (to ensure
consistent timestamping of captured packets) and one to run the system under
test (to ensure consistent response times).

While you can run the tests against a network server, this manual
doesn't describe how to ensure low latency and low jitter
to such system under test.

It's better to use a desktop or server system with sufficient cooling as
thermal throttling is common for laptops running heavy workloads resulting
in jitter and overall inconsistent results.

OS configuration
----------------

To ensure the lowest level of noise in measurement, configure the
system to isolate cores for tcpdump and the system under test.

Red Hat Enterprise Linux 8
^^^^^^^^^^^^^^^^^^^^^^^^^^
To isolate CPUs on RHEL-8, install the following packages:

.. code:: bash

   dnf install -y tuned tuned-utils tuned-profiles-cpu-partitioning


And add the following code to ``/etc/tuned/cpu-partitioning-variables.conf``
file:

.. code::

   isolated_cores=2-10
   no_balance_cores=2-20

Then apply the profile:

.. code:: bash

   tuned-adm profile cpu-partitioning

and restart the system to apply the changes to the kernel.

Then you can install tlsfuzzer dependencies to speed-up the test execution:

.. code:: bash

   dnf install python3 python3-devel tcpdump gmp-devel swig mpfr-devel \
   libmpc openssl-devel make gcc gcc-c++ git libmpc-devel python3-six

   pip3 install m2crypto gmpy gmpy2
   pip3 install --pre tlslite-ng

And the general requirements to collect and analyse timing results:

.. code:: bash

   pip install -r requirements-timing.txt

.. note::

   Because the tests use packet capture to collect timing information and
   they buffer the messages until all of them have been created, the use
   of ``m2crypto``, ``gmpy`` and ``gmpy2`` does not have an effect on collected
   data point, using them will only make tlsfuzzer run the tests at a higher
   frequency.

Testing theory
==============

Because the measurements the test performs are statistical by nature,
the scripts can't just take a mean of observations and compare them with
means of observations of other tests—that will not provide quantifiable
results. This is caused by the fact that the measurements don't follow
a simple and well-defined distribution, in many cases they are
`multimodal
<https://en.wikipedia.org/wiki/Multimodal_distribution>`_
and not `normal <https://en.wikipedia.org/wiki/Normal_distribution>`_.
That means that the scripts need to use statistical tests to check if the
observations differ significantly or not.

Most statistical tests work in terms of hypothesis testing.
The one used in the scripts is called
`Wilcoxon signed-rank test
<https://en.wikipedia.org/wiki/Wilcoxon_signed-rank_test>`_.
After executing it against two sets of observations (samples), it outputs
a "p-value"—a probability of getting such samples, if they were taken from
populations having the same distribution.
A high p-value (close to 1) means that the samples likely came from the
same source while a small value (close to 0, smaller than 0.05) means
that it's unlikely that they came from the same source distribution.

Generally, script assumes that the p-values below 0.05 mean that the values
came from different distributions, i.e. the server behaves differently
for the two provided inputs.

But such small values are expected even if the samples were taken from the same
distribution if the number of performed tests is large, so you need to check
if those values are no more common than expected.

If the samples did indeed come from the same population, then the distribution
of p-values will follow a
`uniform distribution
<https://en.wikipedia.org/wiki/Uniform_distribution_(continuous)>`_ with
values between 0 and 1.

You can use this property to check if not only the failures (small p-values)
occur not more often than expected, but to check for more general inconsistency
in p-values (as higher probability of small p-values means that large
p-values occur less often).

The scripts perform the
`Kolmogorov–Smirnov test
<https://en.wikipedia.org/wiki/Kolmogorov%E2%80%93Smirnov_test>`_ to test
the uniformity of p-values of the Wilcoxon tests.

The test scripts allow setting the sample size as it has impact on the smallest
effect size that the test can detect.
Generally, with Wilcoxon signed-rank test, the sample size must be proportional
to 1/e² to detect effect of size e.
That is, to detect a 0.1% difference between expected values of samples, the
samples must have at least 1000 observations each.
The actual number depends on multiple factors (including the particular
samples in question), but it's a good starting point.

Note that this effect size is proportional to magnitude of any single
observation, at the same time things like size of pre master secret
or size of MAC are constant, thus configuring the server to use fast ciphers
and small key sizes for RSA will make the test detect smaller (absolute)
effect sizes, if they exist.

Finally, the scripts take the pair of samples most dissimilar to each other
and estimate the difference and the 99% confidence interval for the difference
to show the estimated effect size.

You can also use the following
`R
<https://www.r-project.org/>`_ script to calculate the confidence intervals
for the difference between a given pair of samples using the Wilcoxon test:

.. code::

   df <- read.csv('timing.csv', header=F)
   data <- df[,2:length(df[1,])]
   # print headers (names of tests)
   df[,1]
   # run Wilcoxon signed-rank test between second and third sample,
   # report 99% confidence interval for the difference:
   wilcox.test(as.numeric(data[2,]), as.numeric(data[3,]), paired=T, conf.int=T, conf.level=0.99)


To put into practical terms, a run with 10000 observations, checking a server
with a 100µs response time will not detect a timing side channel
that's smaller than 0.01µs (40 cycles on a 4GHz CPU).

Running the tests
=================

To run the tests:

1. Select a machine with sufficient cooling and a multi-core CPU
2. Use methods mentioned before to create isolated cores, watch out for
   hyperthreading
3. For RSA tests use small key (1024 bit), for CBC tests use a fast cipher and
   hash.
4. Start the server on one of the isolated cores, e.g.:

   .. code::

       taskset --cpu-list 2,3 openssl s_server -key key.pem -cert cert.pem -www
5. Start the test script, provide the IDs of different isolated cores:

   .. code::

       PYTHONPATH=. python3 scripts/test-lucky13.py -i lo --repeat 100 --cpu-list 4,5
6. Wait (a long) time
7. Inspect summary of the analysis, or move the test results to a host with
   newer python and analyse it there.

.. note::

   Since both using pinned cores and collecting packets requires root
   permissions, execute the previously mentioned commands as root.

.. warning::

   The tests use ``tcpdump`` to collect packets to a file and analyse it
   later.
   To process tests with large ``--repeat`` parameter, you need a machine
   with a large amount of disk space: at least 350MiB with 20 tests at
   10000 repeats.


Test argument interface
-----------------------

Any test that collects timing information provides the following
argument interface. Specifying the network interface that packet capture should
listen on should be enough to time the tests.

================ ========== ==================================================
 Argument        Required   Description
================ ========== ==================================================
``-i interface`` Yes        Interface to run tcpdump on
``-o dir``       No         Output directory (default ``/tmp``)
``--repeat rep`` No         Repeat each test ``rep`` times (default 100)
``--cpu-list``   No         Core IDs to use for running tcpdump (default none)
================ ========== ==================================================

Executing the test, extraction and analysis
-------------------------------------------

Tests can be executed the same way as any non-timing tests, just make sure the
current user has permissions to run tcpdump or use sudo. As an example, the
Bleichenbacher test is extended to use the timing functionality:

.. code:: bash

   sudo PYTHONPATH=. python scripts/test-bleichenbacher-timing.py -i lo

By default, if ``dpkt`` dependency is available, the extraction will run right
after the timing packet capture.
In case you want to run the extraction on another machine (e.g. you were not
able to install the optional dependencies) you can do this by providing the
log, the packet capture and server port and hostname (or ip) to the analysis
script. Resulting file will be outputted to the specified folder.

.. code:: bash

   PYTHONPATH=. python tlsfuzzer/extract.py -h localhost -p 4433 \
   -c capture.pcap -l log.csv -o /tmp/results/

Timing runner will also launch analysis, if its dependencies are available.
Again, in case you need to run it later, you can do that by providing the
script with an output folder where extraction step put the ``timing.csv``
file.

.. code:: bash

   PYTHONPATH=. python tlsfuzzer/analysis.py -o "/tmp/results"


External timing data
--------------------

The ``extract.py`` can also process data collected by some external source
(be it packet capture closer to server under test or an internal probe
inside the server).

The provided csv file must have a header and one column. While the file
can contain additional data points at the beginning, the very last
data point must correspond to the last connection made by tlsfuzzer.

Place such file in the directory (in this example named ``timings-log.csv``)
with the ``log.csv`` file and execute:

.. code:: bash

   PYTHONPATH=. python tlsfuzzer/extract.py -l /tmp/results/log.csv \
   -o /tmp/results --raw-times /tmp/results/timings-log.csv

.. warning::

   The above mentioned command will overrite the timings extracted from the
   ``capture.pcap`` file!

Then run ``analysis.py`` as in the case of data extracted from ``capture.pcap``
file:

.. code:: bash

   PYTHONPATH=. python tlsfuzzer/analysis.py -o "/tmp/results"


Interpreting the results
========================

As mentioned previously, the script executes tests in two stages, one
is the Wilcoxon signed-rank test between all the samples and then it performs
a self check on the results of those tests.

If that self test fails, you should inspect the individual test p-values.

If one particular set of tests consistently scores low when compared to
other tests (e.g. "invalid MAC in Finished on pos 0",
"invalid MAC in Finished on pos -1" and "invalid padding_length in Finished"
from ``test-bleichenbacher-timing.py``) but high when compared with each-other,
that strongly points to a timing side-channel in the system under test.

If the timing signal has a high relative magnitude (one set of tests
slower than another set by 10%), then you can also use the generated
``box_plot.png`` graph.
For small differences with large sample sizes, the differences will be
statistically detectable, even if not obvious from from the box plot.

Using R you can also generate a graph with median of differences between
samples, but note that this will take about an hour for 21 tests and
samples with 1 million observations each on a 4 core/8 thread 2GHz CPU:

.. code::

   library(tidyr)
   library(ggplot2)
   library(dplyr)
   library(data.table)
   library(boot)
   df <- fread('timing.csv', header=F)
   data <- data.frame(t(df[,2:length(df[1,])]))
   colnames(data) <- as.matrix(df[,1:10])[,1]
   df <- 0
   R = 5000
   rsq <- function(data, indices) {
     d <- data[indices]
     return(mean(d, trim=0.25))
   }
   data2 = replicate(R, 0)
   data2 = cbind(data2)
   date()
   for (i in c(2:length(data[1,]))) {
     a = boot(data[,1]-data[,i], rsq, R=R, parallel="multicore",
              simple=TRUE, ncpus=8)
     data2 = cbind(data2, a$t)
   }
   date()
   data2 = data.frame(data2)
   data2 %>% gather(key="MeasureType", value="Delay") %>%
   ggplot( aes(x=factor(MeasureType, level=colnames(data2)), y=Delay,
               fill=factor(MeasureType, level=colnames(data2)))) +
   geom_violin() + xlab("Test ID") +
   ylab("Trimmed mean of differences [s]") + labs(fill="Test ID")
   colnames(data)


Writing new test scripts
========================
The ``TimingRunner`` repeatedly runs tests with
``tcpdump`` capturing packets in the background.
The timing information is then extracted from that ``tcpdump`` capture,
only the response time to the last client message is extracted from
the capture.

Test structure
--------------

After processing these arguments, one would proceed to write the test as usual,
probably adding a ``sanity`` test case and tests cases relating to the feature
under test. The example script ``test-conversation.py`` can be used as a
starting point.

After it is clear, that all the tests passed, timing of the tests can be
executed.
Please note that any tests with ``sanity`` prefix will be ignored in the
timing run.
Start by importing the ``TimingRunner`` class.
Because the timing information collection adds some extra dependencies, it is
necessary to wrap everything related to timing in an if statement:

.. code:: python

   if TimingRunner.check_tcpdump():

Now, the ``TimingRunner`` class can be initialized with the name of
the currently run test, list of conversations
(``sampled_tests`` in the reference scripts),
output directory (the ``-o`` argument), TLS server host and port, and finally
the network interface from the ``-i`` argument.

Next step is to generate log with random order of test cases for each run. This
is done by calling the function ``generate_log()`` from the ``TimingRunner``
instance. This function takes the familiar ``run_only`` and ``run_exclude``
variables that can filter what tests should be run. Note that this function
will exclude any tests named "sanity". The last argument to this function is
how many times each test should be run (``--repeat`` argument).
The log is saved in the output directory.

The last step is to call ``run()`` function
from the ``TiminingRunner`` instance in order to launch tcpdump and begin
iterating over the tests. Provided you were able to install the timing
dependencies, this will also launch extraction that will process the packet
capture, and output the timing information associated with the test class into
a csv file, and analysis that will generate a report with statistical test
results and supporting plots.
