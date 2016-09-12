from subprocess import Popen, call, PIPE
from threading import Thread, Lock
import time
import logging
import sys

logging.basicConfig(level=logging.DEBUG)
#logging.basicConfig(level=logging.INFO)
#logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)

def process_stdout(name, proc, lock=None):
    for line in iter(proc.stdout.readline, b''):
        line = line.rstrip()
        if lock is not None and b'Using certificate and ' in line:
            lock.release()
            lock = None
        logger.debug("{0}:stdout:{1}".format(name, line))

def process_stderr(name, proc):
    for line in iter(proc.stderr.readline, b''):
        line = line.rstrip()
        logger.debug("{0}:stderr:{1}".format(name, line))

def start_server(server_cmd, client_cert=False):
    args = ['PYTHONPATH=.', 'python', '-u', server_cmd, 'server',
            '-k', 'tests/serverX509Key.pem',
            '-c', 'tests/serverX509Cert.pem']
    if client_cert:
        args += ['--reqcert']
    args += ['localhost:4433']
    lock = Lock()
    lock.acquire()
    ret = Popen(" ".join(args),
               shell=True, stdout=PIPE, stderr=PIPE, bufsize=1)
    thr_stdout = Thread(target=process_stdout, args=('server', ret, lock))
    thr_stdout.daemon = True
    thr_stdout.start()
    thr_stderr = Thread(target=process_stderr, args=('server', ret))
    thr_stderr.daemon = True
    thr_stderr.start()
    # wait for server to start
    time.sleep(1)
    return ret, thr_stdout, thr_stderr


def run_clients(scripts, srv, args=tuple()):
    good = 0
    bad = 0
    for script in scripts:
        logger.info("{0}:started".format(script))
        proc_args = ['PYTHONPATH=.', 'python', '-u',
                     'scripts/{0}'.format(script)]
        proc_args.extend(args)
        proc = Popen(" ".join(proc_args),
                     shell=True, stdout=PIPE, stderr=PIPE, bufsize=1)
        thr_stdout = Thread(target=process_stdout, args=(script, proc))
        thr_stderr = Thread(target=process_stderr, args=(script, proc))
        thr_stdout.start()
        thr_stderr.start()
        thr_stdout.join()
        thr_stderr.join()
        proc.wait()
        ret = proc.returncode
        if srv.returncode is not None:
            logger.critical("Server process not active")
        if ret == 0:
            good += 1
            logger.info("{0}:finished".format(script))
        else:
            bad += 1
            logger.error("{0}:failure:{1}".format(script, ret))
    return good, bad


def run_rsa_cert_tests(server_cmd):
    simple_scripts = ['test-aes-gcm-nonces.py',
                      'test-atypical-padding.py',
                      'test-bleichenbacher-workaround.py',
                      'test-conversation.py',
                      'test-cve-2016-2107.py',
                      'test-dhe-rsa-key-exchange.py',
                      'test-dhe-rsa-key-exchange-signatures.py',
                      'test-dhe-rsa-key-exchange-with-bad-messages.py',
                      'test-early-application-data.py',
                      'test-ecdhe-rsa-key-exchange.py',
                      'test-ecdhe-rsa-key-exchange-with-bad-messages.py',
                      'test-empty-extensions.py',
                      # test requires renegotiation support
                      #'test-extended-master-secret-extension.py',
                      'test-fuzzed-ciphertext.py',
                      'test-fuzzed-finished.py',
                      'test-fuzzed-MAC.py',
                      'test-fuzzed-padding.py',
                      'test-hello-request-by-client.py',
                      # test requires renegotiation support
                      #'test-interleaved-application-data-and-fragmented-handshakes-in-renegotiation.py',
                      #'test-interleaved-application-data-in-renegotiation.py',
                      'test-invalid-cipher-suites.py',
                      # tlslite-ng just ignores this field
                      #'test-invalid-compression-methods.py',
                      'test-invalid-content-type.py',
                      'test-invalid-rsa-key-exchange-messages.py',
                      # not verified correctly by tlslite-ng
                      #'test-invalid-session-id.py',
                      'test-invalid-version.py',
                      # test requires renegotiation support
                      #'test-openssl-3712.py',
                      'test-record-layer-fragmentation.py',
                      'test-sessionID-resumption.py',
                      'test-sslv2-connection.py',
                      'test-sslv2-force-cipher-3des.py',
                      'test-sslv2-force-cipher-non3des.py',
                      'test-sslv2-force-cipher.py',
                      'test-sslv2-force-export-cipher.py',
                      'test-sslv2hello-protocol.py',
                      # SSLv3 is disabled by default
                      #'test-SSLv3-padding.py',
                      'test-TLSv1_2-rejected-without-TLSv1_2.py',
                      'test-truncating-of-client-hello.py',
                      'test-truncating-of-finished.py',
                      'test-truncating-of-kRSA-client-key-exchange.py',
                      'test-unsupported-cuve-fallback.py',
                      'test-version-numbers.py',
                      'test-zero-length-data.py']

    good = 0
    bad = 0
    srv, srv_out, srv_err = start_server(server_cmd)
    logger.info("Server process started")

    try:
        n_good, n_bad = run_clients(simple_scripts, srv)
        good += n_good
        bad += n_bad
    finally:
        try:
            logging.debug("Killing server process")
            srv.send_signal(15)  # SIGTERM
            srv.wait()
            logging.debug("Server process killed")
        except OSError:
            logging.debug("Can't kill server process")
    srv_err.join(5)
    srv_out.join(5)

    client_certs = ['test-certificate-verify-malformed-sig.py',
                    'test-certificate-verify.py',
                    'test-rsa-sigs-on-certificate-verify.py']

    srv, srv_out, srv_err = start_server(server_cmd, client_cert=True)
    logger.info("Server process started")

    try:
        n_good, n_bad = run_clients(client_certs, srv,
                                    ['-k', 'tests/clientX509Key.pem',
                                     '-c', 'tests/clientX509Cert.pem'])
    finally:
        try:
            logging.debug("Killing server process")
            srv.send_signal(15)  # SIGTERM
            srv.wait()
            logging.debug("Server process killed")
        except OSError:
            logging.debug("Can't kill server process")
    srv_err.join(5)
    srv_out.join(5)

    return (good, bad)

def main():
    if len(sys.argv) < 2:
        print("provide path to tlslite-ng tls.py server")
        sys.exit(2)

    server_cmd = sys.argv[1]
    good, bad = run_rsa_cert_tests(server_cmd)

    logging.shutdown()

    print("Ran {0} scripts".format(good + bad))
    print("good: {0}".format(good))
    print("bad: {0}".format(bad))

    if bad > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
