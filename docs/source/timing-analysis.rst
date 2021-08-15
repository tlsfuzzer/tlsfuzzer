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
   no_balance_cores=2-10

Then apply the profile:

.. code:: bash

   tuned-adm profile cpu-partitioning

and restart the system to apply the changes to the kernel.

Then you can install tlsfuzzer dependencies to speed-up the test execution:

.. code:: bash

   dnf install python3 python3-devel tcpdump gmp-devel swig mpfr-devel \
   libmpc openssl-devel make gcc gcc-c++ git libmpc-devel python3-six

   pip3 install m2crypto gmpy2
   pip3 install --pre tlslite-ng

And the general requirements to collect and analyse timing results:

.. code:: bash

   pip install -r requirements-timing.txt

.. note::

   Because the tests use packet capture to collect timing information and
   they buffer the messages until all of them have been created, the use
   of ``m2crypto`` and ``gmpy2`` does not have an effect on collected
   data points, using them will only make tlsfuzzer run the tests at a higher
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
Scripts use
`Wilcoxon signed-rank test
<https://en.wikipedia.org/wiki/Wilcoxon_signed-rank_test>`_
and the
`Sign test
<https://en.wikipedia.org/wiki/Sign_test>`_ to compare samples.
After executing it against two sets of observations (samples), it outputs
a "p-value"—a probability of getting such samples, if they were taken from
the same population.
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
the uniformity of p-values of the Wilcoxon tests and the sign test.

The test scripts allow setting the sample size as it has impact on the smallest
effect size that the test can detect.
Generally, with both of the used tests, the sample size must be proportional
to 1/e² to detect effect of size e.
That is, to detect a 0.1% difference between expected values of samples, the
samples must have at least 1000 observations each.
The actual number depends on multiple factors (including the particular
samples in question), but it's a good starting point.
Also, it means that if you wish to decrease the reported confidence interval
by a factor of 10, you must execute the script with 100 times as many
repetitions (as 10²=100).

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


With large sample sizes, to avoid exhausting available memory and to speed up
the analysis, you can skip the generation of some graphs using the
``--no-ecdf-plot``, ``--no-scatter-plot`` and ``--no-conf-interval-plot``.
That last option disables generation of the ``bootstrapped_means.csv`` file
too.

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


Combining results from multiple runs
------------------------------------

You can use the ``combine.py`` script to combine the results from runs.

The script checks if the set of executed probes match in all the files,
but you need to ensure that the environments of the test execution match
too.

To combine the runs, provide the output directory (``out-dir`` here) and
paths to one or more ``timing.csv`` files:

.. code:: bash

   PYTHONPATH=. python tlsfuzzer/combine.py -o out-dir \
   in_1596892760/timing.csv in_1596892742/timing.csv

.. warning::

   The script overwrites the ``timing.csv`` in the output directory!

After combining the ``timing.csv`` files, execute analysis as usual.

.. tip::

   ``combine.py`` is the only script able to read the old format of
   ``timing.csv`` files. Use it with a single input file to covert from
   old file format (where all results for a given probe ware listed in a single
   line) to the new file format (where all results for a given probe are
   in a single column)

Interpreting the results
========================

You should start the inspection of test results with the ``scatter_plot.png``
graph. It plots all of the collected connection times. There is also a
zoomed-in version that will be much more readable in case of much larger
outliers. You can find it in the ``scatter_plot_zoom_in.png`` file.
If you can see that there is a periodicity to the collected measurements, or
the values can be collected in similarly looking groups, that means that
the data is
`autocorrelated
<https://en.wikipedia.org/wiki/Autocorrelation>`_ (or, in other words,
not-independent) and simple summary statistics like
mean, median, or quartiles are not representative of the samples.

The next set of graphs show the overall shape of the samples.
The ``box_plot.png`` shows the 5th
`percentile
<https://en.wikipedia.org/wiki/Percentile>`_, 1st `quartile
<https://en.wikipedia.org/wiki/Quartile>`_, median, 3rd
quartile and 95th percentile.
The ``ecdf_plot.png`` shows the `measured (that is, empirical) cumulative
distribution function
<https://en.wikipedia.org/wiki/Empirical_distribution_function>`_.
The ``ecdf_plot_zoom_in.png`` shows only the values between 1st and 95th
percentile, useful in case of few very large outliers.
The "steps" visible in the graph inform us if the distibution is
unimodal (like the common normal distribution) or if it is
`multimodal
<https://en.wikipedia.org/wiki/Multimodal_distribution>`_.
Multimodality is another property that makes simple summary statistics
like mean or median not representative of the sample.

To compare autocorrelated samples we need to compare the differences
between pairs of samples.
The ``diff_scatter_plot.png`` shows the differences of all the samples
when compared to the first sample (numbered 0).
The ``diff_ecdf_plot.png`` is the ECDF counterpart to the scatter plot.
Here, if the graph is
`symmetrical
<https://en.wikipedia.org/wiki/Symmetric_probability_distribution>`_ then the
results from the Wilcoxon signed-rank test are meaningful. If the graph
is asymmetric focus on sign test results.
The ``diff_ecdf_plot_zoom_in_98.png``, ``diff_ecdf_plot_zoom_in_33.png``,
and ``diff_ecdf_plot_zoom_in_10.png`` show just the central 98, 33, and 10
percentiles respectively of the graph (to make estimating small differences
between samples easier).

Finally, the ``conf_interval_plot_mean.png``,
``conf_interval_plot_median.png``, ``conf_interval_plot_trim_mean_05.png``,
``conf_interval_plot_trim_mean_25.png``, and ``conf_interval_plot_trimean.png``
show the mean, median, trimmed mean (5%), trimmed mean (25%), and trimean
respecively, of the differences between samples together with
`bootstrapped
<https://en.wikipedia.org/wiki/Bootstrapping_(statistics)>`_ confidence
interval for them.
For an implementation without a timing side channel present, all the graphs
should intersect with the horizonal 0 line.
If a graph does not intersect with the 0 line, then the number of heights
of it from the 0 line suggests how strong is the confidence in the
presence of side channel on an exponential scale.

As mentioned previously, the script executes tests in three stages, first
is the Wilcoxon signed-rank test and sign test between all the samples,
second is the uniformity test of those results, third is the Friedman test.

.. warning::

   The implementation of Friedman test uses an approximation using Chi-squared
   distribution. That means the results of it are reliable only with many
   samples (at least 5, optimally 10). You should ignore it for such small
   runs. It's also invalid in case of just two samples (used conversations).

The sign test is performed in three different ways: the default, used for
determining presence of the timing side-channel, is the two-sided variant,
saved in the ``report.csv`` file as the ``Sign test``. The two other ways,
the ``Sign test less`` and ``Sign test greater`` test the hypothesis that
the one sample stochastically dominates the other. High p-values here aren't
meangingful (i.e. you can get a p-value == 1 even if the alternative is not
statistically significant even at alpha=0.05).
Very low values of a ``Sign test less`` mean that the *second* sample
is unlikely to be smaller than the *first* sample.
Those tests are more sensitive than the confidence intervals for median, so
you can use them to test the theory if the timing signal depends on some
parameters, like the length of pre-master secret in RSA key exchange or place
of the first mismatched byte in CBC MAC.

The code also calculates the
`dependent t-test for paired samples
<https://en.wikipedia.org/wiki/Student%27s_t-test#Dependent_t-test_for_paired_samples>`_,
but as the timings generally don't follow the normal distribution, it severly
underestimates the difference between samples (it is strongly influenced by
outliers). The results from it are not taken into account to decide failure of
the overall timing test.

If either the KS-tests of uniformity of p-values, or the Friedman test fails,
you should inspect the individual test p-values.

If one particular set of tests consistently scores low when compared to
other tests (e.g. "very long (96-byte) pre master secret" and
"very long (124-byte) pre master secret"
from ``test-bleichenbacher-timing.py``) but high when compared with each-other,
that strongly points to a timing side-channel in the system under test.

If the timing signal has a high relative magnitude (one set of tests
slower than another set by 10%), then you can also use the generated
``box_plot.png`` graph to see it.
For small differences with large sample sizes, the differences will be
statistically detectable, even if not obvious from from the box plot.
You can use the ``conf_interval_plot*.png`` graphs to see the difference
between samples and the first sample together with the 95% confidence
interval for them.

The script prints the numerical value for confidence interval for mean, median,
trimmed mean (with 5% of observervations on either end ignored), trimmed mean
(with 25% of smalles and biggest observations ignored), and trimean of
differences of the pair of two most dissimilar probes.
It also writes them to the ``report.txt`` file.

The ``report.csv`` file includes the exact p-values for the statistical
tests executed as well as the calculated descriptive statistics of
distribution of differences: the mean, standard deviation (SD), median,
interquartile range (IQR, as well as the
`median absolute deviation
<https://en.wikipedia.org/wiki/Median_absolute_deviation>`_ (MAD).
Note that the mean and SD are very sensitive to outliers, the other three
measures are more robust. The calculated MAD already includes the conversion
factor so for a normal distribution it can be compared directly to SD.

The ``sample_stats.csv`` file include the calculated mean, median, and MAD
for the samples themselves (i.e. not the differences between samples).
You can use this data to estimate the smallest detectable difference between
samples for a given sample size.

Using R you can also manually generate ``conf_interval_plot_mean.png`` graph,
but note that this will take about an hour for 21 tests and
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
