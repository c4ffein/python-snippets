from socket import socketpair, create_connection
from unittest import TestCase, mock
from unittest import main as unittest_main
from unittest.mock import patch
from time import sleep
from ssl import SSLError, wrap_socket
import socket
import sys
from threading import Thread

from src.pinned_ssl_context import make_pinned_ssl_context

HOST, PORT = "localhost", 8888


# TODO : Next doc better
"""
- Create a Self-Signed Root Certificate Authority (CA)
  ```
  openssl req -x509 -newkey rsa:4096 -keyout root_ca.key -out root_ca.crt -days 3650 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=FakeRoot"
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


def start_worker_thread(func):
    end_of_worker_asked = False

    def wrapper(*args, **kwargs):
        nonlocal end_of_worker_asked
        worker_thread = Thread(target=worker, args=args, kwargs=kwargs)
        worker_thread.start()
        sleep(0.0001)  # Should do better but who cares
        result = func(*args, **kwargs)
        end_of_worker_asked = True
        worker_thread.join(timeout=0.1)
        if worker_thread.is_alive():
            raise Exception("WORKER THREAD NOT KILLED")
        return result

    def worker(*args, **kwargs):
        nonlocal end_of_worker_asked
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Make it reusable ASAP
            sock.bind((HOST, PORT))
            sock.settimeout(0.01)
            sock.listen(5)
            while True:
                if end_of_worker_asked:
                    break
                try:
                    conn, addr = sock.accept()
                    secure_conn = wrap_socket(
                        conn, certfile="certs/server.crt", keyfile="certs/server.key", server_side=True
                    )
                    handle_secure_connection(secure_conn)
                    secure_conn.close()
                except socket.timeout:
                    secure_conn.close()  # May be useless for now
                except SSLError as e:
                    if e.args == (1, "[SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca (_ssl.c:1129)"):
                        break  # It is expected that the client may try to reach us with a missing CA
                    if e.args == (1, "[SSL: SSLV3_ALERT_BAD_CERTIFICATE] sslv3 alert bad certificate (_ssl.c:1129)"):
                        break  # It is expected that the client may try to reach us with a missing CA
                    raise e
    return wrapper


def handle_secure_connection(conn):
    try:
        data = conn.recv(1024)
        conn.sendall(b"HTTP/1.0 200 OK\r\n\r\nHello, World!")
    except:
        pass


class PinnedSSLTest(TestCase):
    @patch("ssl.SSLSocket.getpeercert")
    def test_those_works_if_we_create_2_contexts_with_2_different_certificates(self, mocked_getpeercert):
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
    def test_will_fail_if_already_opened_socket_gets_wrapped_without_ca(self):
        context = make_pinned_ssl_context("f300c720c0f6ecb18bb41bf7930346c660bb4b29a7089a3d2abb0f3ee9f12f5b")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((HOST, PORT))
            with self.assertRaises(Exception) as ec:
                with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as ssock:
                    pass
        expected_ssl_error_str = (
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "unable to get local issuer certificate (_ssl.c:1129)"
        )
        self.assertEqual(ec.exception.args, (1, expected_ssl_error_str))

    @start_worker_thread
    def test_will_fail_if_already_opened_socket_gets_wrapped_with_incorrect_checksum(self):
        context = make_pinned_ssl_context("d711a9468e2c4ee6ab4ea244afff8e24b8e8fdd2bdcfc98ce6e5bb9d43e17844")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((HOST, PORT))
            with self.assertRaises(Exception) as ec:
                with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as ssock:
                    pass
        self.assertEqual(ec.exception.args, ("Incorrect certificate checksum",))

    @start_worker_thread
    def test_will_fail_if_already_opened_socket_gets_wrapped_with_an_incorrect_server_hostname(self):
        context = make_pinned_ssl_context("f300c720c0f6ecb18bb41bf7930346c660bb4b29a7089a3d2abb0f3ee9f12f5b")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((HOST, PORT))
            with self.assertRaises(Exception) as ec:
                with context.wrap_socket(client_socket, server_hostname="wrong.c4ffein.dev") as ssock:
                    pass

    @start_worker_thread
    def test_will_work_if_already_opened_socket_gets_wrapped_with_correct_infos(self):
        context = make_pinned_ssl_context("f300c720c0f6ecb18bb41bf7930346c660bb4b29a7089a3d2abb0f3ee9f12f5b")
        context.load_verify_locations(cafile="certs/root_ca.crt")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((HOST, PORT))
            with context.wrap_socket(client_socket, server_hostname="fake.c4ffein.dev") as ssock:
                ssock.sendall(b"Hello, server!")
                data = ssock.recv(1024)
                self.assertEqual(data, b"HTTP/1.0 200 OK\r\n\r\nHello, World!")


    ####def test_check_is_called_if_connecting_on_new_socket(self):
    # TODO : For all related tests
    ####    raise Exception("TODO")

    ####def test_called_with_correct_params_so_that_regular_verif_and_so_getpeercert_is_enough(self):
    # TODO : For all related tests
    ####    raise Exception("TODO")


if __name__ == "__main__":
    unittest_main()
