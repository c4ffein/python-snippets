"""
How to create the certificates for testing:
- Create a Self-Signed Root Certificate Authority (CA)
  ```
  openssl req -x509 -newkey rsa:4096 -keyout root_ca.key -out root_ca.crt -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=FakeRoot" -addext "keyUsage=critical,digitalSignature,keyCertSign"
  ```
- Create a Server Certificate Signing Request (CSR) for your server certificate
  ```
  openssl req -newkey rsa:4096 -nodes -keyout server.key -out server.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=fake.c4ffein.dev"
  ```
- Sign the Server Certificate with the Root CA, `server.crt` is your signed server certificate
  ```
  openssl x509 -req -days 3649 -in server.csr -CA root_ca.crt -CAkey root_ca.key -CAcreateserial -out server.crt
  ```
- Use CA and certs
  - client: use `root_ca.crt`
  - server: use `server.crt` and `server.key`
"""

import socket
from ssl import SSLContext, SSLError
from threading import Thread
from time import sleep
from unittest import TestCase
from unittest import main as unittest_main
from unittest.mock import ANY, patch

from src.pinned_ssl_context import make_pinned_ssl_context

HOST, PORT = "localhost", 8888


def start_worker_thread(func):
    end_of_worker_asked = False
    worker_events = []  # Log of events that occurred in the worker thread

    def wrapper(*args, **kwargs):
        nonlocal end_of_worker_asked
        # Attach worker events to the test instance for verification (before starting worker)
        if args and hasattr(args[0], "__class__"):
            args[0].worker_events = worker_events
        worker_thread = Thread(target=worker, args=args, kwargs=kwargs)
        worker_thread.start()
        # No sleep needed - worker events verification handles timing variations
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            # Always clean up worker thread, even if test fails
            end_of_worker_asked = True
            worker_thread.join(timeout=0.05)  # 50ms to ensure reliability on CI machines
            if worker_thread.is_alive():
                raise Exception("WORKER THREAD NOT KILLED")
            # Give OS time to fully release the socket before next test
            sleep(0.01)  # 10ms is minimum to avoid "Address already in use"

    def worker(*args, **kwargs):
        nonlocal end_of_worker_asked
        worker_events.append("worker_started")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Make it reusable ASAP
                sock.bind((HOST, PORT))
                worker_events.append("bind_successful")
                sock.settimeout(0.001)  # Reduced to 1ms for fast polling
                sock.listen(5)
                worker_events.append("listening")
                while True:
                    if end_of_worker_asked:
                        worker_events.append("worker_exit_requested")
                        break
                    ssl_context = SSLContext()
                    ssl_context.load_cert_chain(certfile="certs/server.crt", keyfile="certs/server.key")
                    try:
                        conn, addr = sock.accept()
                        worker_events.append("connection_accepted")
                    except socket.timeout:
                        continue  # Normal polling - keep trying until end_of_worker_asked
                    conn.settimeout(0.02)  # 20ms - minimum for reliable SSL handshake
                    worker_events.append("attempting_ssl_handshake")
                    try:
                        secure_conn = ssl_context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
                        secure_conn.settimeout(0.02)  # 20ms - minimum for reliable SSL handshake
                        worker_events.append("socket_wrapped")
                        secure_conn.do_handshake()
                        worker_events.append("handshake_complete")
                        handle_secure_connection(secure_conn)
                        secure_conn.close()
                        worker_events.append("connection_successful")
                    except socket.timeout:
                        try:
                            secure_conn.close()
                        except Exception:
                            pass
                        conn.close()
                        worker_events.append("connection_timeout")
                    except SSLError as e:
                        try:
                            secure_conn.close()
                        except Exception:
                            pass
                        conn.close()
                        # These SSL errors are expected as part of the tests - log and continue silently
                        error_msg = str(e.args[1]) if len(e.args) > 1 else str(e)
                        if "TLSV1_ALERT_UNKNOWN_CA" in error_msg:
                            worker_events.append("ssl_unknown_ca")
                            continue  # Expected: client with missing CA
                        if "SSLV3_ALERT_BAD_CERTIFICATE" in error_msg:
                            worker_events.append("ssl_bad_certificate")
                            continue  # Expected: client with bad certificate
                        # For other SSL errors, also log and continue silently - they're part of the test scenarios
                        worker_events.append(f"ssl_error: {type(e).__name__}: {e.args}")
                        continue
                    except (OSError, ConnectionResetError, BrokenPipeError) as e:
                        conn.close()
                        worker_events.append(f"connection_error: {type(e).__name__}: {e.args}")
                        continue
                    except Exception as e:
                        conn.close()
                        worker_events.append(f"unexpected_error: {type(e).__name__}: {e.args}")
                        continue
        except Exception as e:
            # Log any worker failures (bind errors, unexpected exceptions, etc.)
            worker_events.append(f"worker_failed: {type(e).__name__}: {e}")
        worker_events.append("worker_ended")

    return wrapper


def handle_secure_connection(conn):
    try:
        data = conn.recv(1024)
        conn.sendall(b"HTTP/1.0 200 OK\r\n\r\nHello, Client! Answering: '" + data + b"'")
    except Exception:
        pass


class PinnedSSLTest(TestCase):
    @patch("ssl.SSLSocket.getpeercert")
    def test_multiple_contexts_correctly_store_different_certificates(self, mocked_getpeercert):
        context_a = make_pinned_ssl_context("d711a9468e2c4ee6ab4ea244afff8e24b8e8fdd2bdcfc98ce6e5bb9d43e17844")
        context_b = make_pinned_ssl_context("960284fdd51e3651b8ae998cfc82ed2104ee306d3f8ca2f066c4a7b76a47430f")
        mocked_getpeercert.return_value = b"checksum_a"
        context_a.sslsocket_class.check_pinned_cert(context_a.sslsocket_class)
        mocked_getpeercert.return_value = b"checksum_b"
        with self.assertRaises(Exception) as e:
            context_a.sslsocket_class.check_pinned_cert(context_a.sslsocket_class)
        self.assertEqual(e.exception.args, ("Incorrect certificate checksum",))
        mocked_getpeercert.return_value = b"checksum_b"
        context_b.sslsocket_class.check_pinned_cert(context_b.sslsocket_class)
        mocked_getpeercert.return_value = b"checksum_a"
        with self.assertRaises(Exception) as e:
            context_b.sslsocket_class.check_pinned_cert(context_b.sslsocket_class)
        self.assertEqual(e.exception.args, ("Incorrect certificate checksum",))

    @start_worker_thread
    def test_already_opened_socket_that_gets_wrapped_without_ca_will_fail(self):
        context = make_pinned_ssl_context("30152bbe563ad828f53944fcbfe8851afc620943f8b97228cb16822636a786b6")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)  # Prevent client from hanging
            client_socket.connect((HOST, PORT))
            with self.assertRaises(Exception) as ec:
                with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev"):
                    pass
        expected_ssl_error_str = (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate ("
        )
        self.assertEqual(ec.exception.args, (1, ANY))
        self.assertEqual(ec.exception.args[1][:100], expected_ssl_error_str)
        # Verify that the worker thread went through the expected flow
        # Due to timing, worker may be interrupted during handshake
        expected_hung = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
        ]
        expected_with_error = expected_hung + ["ssl_unknown_ca"]
        expected_complete = expected_with_error + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_hung, expected_with_error, expected_complete])

    @start_worker_thread
    def test_already_opened_socket_that_gets_wrapped_with_incorrect_checksum_will_fail(self):
        context = make_pinned_ssl_context("d711a9468e2c4ee6ab4ea244afff8e24b8e8fdd2bdcfc98ce6e5bb9d43e17844")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            client_socket.connect((HOST, PORT))
            with self.assertRaises(Exception) as ec:
                with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev"):
                    pass
        self.assertEqual(ec.exception.args, ("Incorrect certificate checksum",))
        # Worker completes successfully - checksum is verified client-side after SSL handshake
        expected_hung = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
        ]
        expected_minimal = expected_hung + ["handshake_complete", "connection_successful"]
        expected_complete = expected_minimal + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_hung, expected_minimal, expected_complete])

    @start_worker_thread
    def test_already_opened_socket_that_gets_wrapped_with_an_incorrect_server_hostname_will_fail(self):
        context = make_pinned_ssl_context("30152bbe563ad828f53944fcbfe8851afc620943f8b97228cb16822636a786b6")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            client_socket.connect((HOST, PORT))
            with self.assertRaises(Exception) as ec:
                with context.wrap_socket(client_socket, server_hostname="wrong.c4ffein.dev"):
                    pass
        expected_ssl_error_str = (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "Hostname mismatch, certificate is not valid for 'wrong.c4ffein.dev'. ("
        )
        self.assertEqual(ec.exception.args, (1, ANY))
        self.assertEqual(ec.exception.args[1][:130], expected_ssl_error_str)
        # Worker sees ssl_bad_certificate from client rejecting hostname
        expected_hung = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
        ]
        expected_with_error = expected_hung + ["ssl_bad_certificate"]
        expected_complete = expected_with_error + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_hung, expected_with_error, expected_complete])

    @start_worker_thread
    def test_already_opened_socket_that_gets_wrapped_with_correct_infos_will_work(self):
        context = make_pinned_ssl_context("30152bbe563ad828f53944fcbfe8851afc620943f8b97228cb16822636a786b6")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            client_socket.connect((HOST, PORT))
            with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as secure_client_socket:
                secure_client_socket.sendall(b"Hello, Server!")
                data = secure_client_socket.recv(1024)
                self.assertEqual(data, b"HTTP/1.0 200 OK\r\n\r\nHello, Client! Answering: 'Hello, Server!'")
        # Verify that the connection was successful from the worker's perspective
        # Due to timing, worker may or may not log final exit events
        expected_events_minimal = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
            "handshake_complete",
            "connection_successful",
        ]
        expected_events_complete = expected_events_minimal + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_events_minimal, expected_events_complete])

    @start_worker_thread
    def test_context_that_connects_without_ca_will_fail(self):
        context = make_pinned_ssl_context("30152bbe563ad828f53944fcbfe8851afc620943f8b97228cb16822636a786b6")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as secure_client_socket:
                with self.assertRaises(Exception) as ec:
                    secure_client_socket.connect((HOST, PORT))
        expected_ssl_error_str = (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate ("
        )
        self.assertEqual(ec.exception.args, (1, ANY))
        self.assertEqual(ec.exception.args[1][:100], expected_ssl_error_str)
        # Worker sees ssl_unknown_ca from client without CA
        expected_hung = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
        ]
        expected_with_error = expected_hung + ["ssl_unknown_ca"]
        expected_complete = expected_with_error + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_hung, expected_with_error, expected_complete])

    @start_worker_thread
    def test_context_that_connects_with_incorrect_checksum_will_fail(self):
        context = make_pinned_ssl_context("d711a9468e2c4ee6ab4ea244afff8e24b8e8fdd2bdcfc98ce6e5bb9d43e17844")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as secure_client_socket:
                with self.assertRaises(Exception) as ec:
                    secure_client_socket.connect((HOST, PORT))
        self.assertEqual(ec.exception.args, ("Incorrect certificate checksum",))

        # Worker completes successfully
        expected_hung = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
        ]
        expected_minimal = expected_hung + ["handshake_complete", "connection_successful"]
        expected_complete = expected_minimal + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_hung, expected_minimal, expected_complete])

    @start_worker_thread
    def test_context_that_connects_with_an_incorrect_server_hostname_will_fail(self):
        context = make_pinned_ssl_context("30152bbe563ad828f53944fcbfe8851afc620943f8b97228cb16822636a786b6")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            with context.wrap_socket(client_socket, server_hostname="wrong.c4ffein.dev") as secure_client_socket:
                with self.assertRaises(Exception) as ec:
                    secure_client_socket.connect((HOST, PORT))
        expected_ssl_error_str = (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "Hostname mismatch, certificate is not valid for 'wrong.c4ffein.dev'. ("
        )
        self.assertEqual(ec.exception.args, (1, ANY))
        self.assertEqual(ec.exception.args[1][:130], expected_ssl_error_str)

        # Worker sees ssl_bad_certificate from client rejecting hostname
        expected_hung = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
        ]
        expected_with_error = expected_hung + ["ssl_bad_certificate"]
        expected_complete = expected_with_error + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_hung, expected_with_error, expected_complete])

    @start_worker_thread
    def test_context_that_connects_with_correct_infos_will_work(self):
        context = make_pinned_ssl_context("30152bbe563ad828f53944fcbfe8851afc620943f8b97228cb16822636a786b6")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as secure_client_socket:
                secure_client_socket.connect((HOST, PORT))
                secure_client_socket.sendall(b"Hello, Server!")
                data = secure_client_socket.recv(1024)
                self.assertEqual(data, b"HTTP/1.0 200 OK\r\n\r\nHello, Client! Answering: 'Hello, Server!'")

        # Worker completes successfully
        expected_minimal = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
            "handshake_complete",
            "connection_successful",
        ]
        expected_complete = expected_minimal + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_minimal, expected_complete])

    @start_worker_thread
    def test_context_that_connects_ex_without_ca_will_fail(self):
        context = make_pinned_ssl_context("30152bbe563ad828f53944fcbfe8851afc620943f8b97228cb16822636a786b6")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as secure_client_socket:
                with self.assertRaises(Exception) as ec:
                    secure_client_socket.connect_ex((HOST, PORT))
        expected_ssl_error_str = (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate ("
        )
        self.assertEqual(ec.exception.args, (1, ANY))
        self.assertEqual(ec.exception.args[1][:100], expected_ssl_error_str)

        # Worker sees ssl_unknown_ca from client without CA
        expected_hung = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
        ]
        expected_with_error = expected_hung + ["ssl_unknown_ca"]
        expected_complete = expected_with_error + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_hung, expected_with_error, expected_complete])

    @start_worker_thread
    def test_context_that_connects_ex_with_incorrect_checksum_will_fail(self):
        context = make_pinned_ssl_context("d711a9468e2c4ee6ab4ea244afff8e24b8e8fdd2bdcfc98ce6e5bb9d43e17844")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as secure_client_socket:
                with self.assertRaises(Exception) as ec:
                    secure_client_socket.connect_ex((HOST, PORT))
        self.assertEqual(ec.exception.args, ("Incorrect certificate checksum",))

        # Worker completes successfully
        expected_hung = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
        ]
        expected_minimal = expected_hung + ["handshake_complete", "connection_successful"]
        expected_complete = expected_minimal + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_hung, expected_minimal, expected_complete])

    @start_worker_thread
    def test_context_that_connects_ex_with_an_incorrect_server_hostname_will_fail(self):
        context = make_pinned_ssl_context("30152bbe563ad828f53944fcbfe8851afc620943f8b97228cb16822636a786b6")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            with context.wrap_socket(client_socket, server_hostname="wrong.c4ffein.dev") as secure_client_socket:
                with self.assertRaises(Exception) as ec:
                    secure_client_socket.connect_ex((HOST, PORT))
        expected_ssl_error_str = (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "Hostname mismatch, certificate is not valid for 'wrong.c4ffein.dev'. ("
        )
        self.assertEqual(ec.exception.args, (1, ANY))
        self.assertEqual(ec.exception.args[1][:130], expected_ssl_error_str)

        # Worker sees ssl_bad_certificate from client rejecting hostname
        expected_hung = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
        ]
        expected_with_error = expected_hung + ["ssl_bad_certificate"]
        expected_complete = expected_with_error + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_hung, expected_with_error, expected_complete])

    @start_worker_thread
    def test_context_that_connects_ex_with_correct_infos_will_work(self):
        context = make_pinned_ssl_context("30152bbe563ad828f53944fcbfe8851afc620943f8b97228cb16822636a786b6")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.settimeout(1.0)
            with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as secure_client_socket:
                secure_client_socket.connect_ex((HOST, PORT))
                secure_client_socket.sendall(b"Hello, Server!")
                data = secure_client_socket.recv(1024)
                self.assertEqual(data, b"HTTP/1.0 200 OK\r\n\r\nHello, Client! Answering: 'Hello, Server!'")

        # Worker completes successfully
        expected_minimal = [
            "worker_started",
            "bind_successful",
            "listening",
            "connection_accepted",
            "attempting_ssl_handshake",
            "socket_wrapped",
            "handshake_complete",
            "connection_successful",
        ]
        expected_complete = expected_minimal + ["worker_exit_requested", "worker_ended"]
        self.assertIn(self.worker_events, [expected_minimal, expected_complete])


if __name__ == "__main__":
    unittest_main()
