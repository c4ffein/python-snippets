import os
from hashlib import sha256
from ssl import (
    CERT_NONE,
    CERT_REQUIRED,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    Purpose,
    SSLContext,
    SSLSocket,
    _ASN1Object,
    _ssl,
)
from sys import flags as sys_flags


def make_pinned_ssl_context(pinned_sha_256):
    # TODO Document
    # TODO Explain can be found here
    # TODO Copy
    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() != pinned_sha_256:  # TODO : Check this is enough
                raise Exception("Incorrect certificate checksum")  # TODO : Better

        def connect(self, addr):  # Needed for when the context creates a new connection
            r = super().connect(addr)
            self.check_pinned_cert()
            return r

        def connect_ex(self, addr):  # Needed for when the context creates a new connection
            r = super().connect_ex(addr)
            self.check_pinned_cert()
            return r

    class PinnedSSLContext(SSLContext):
        sslsocket_class = PinnedSSLSocket

        def wrap_socket(  # Needed for when we wrap an exising socket
            self,
            sock,
            server_side=False,
            do_handshake_on_connect=True,
            suppress_ragged_eofs=True,
            server_hostname=None,
            session=None,
        ):
            ws = super().wrap_socket(
                sock,
                server_side=server_side,
                do_handshake_on_connect=do_handshake_on_connect,
                suppress_ragged_eofs=suppress_ragged_eofs,
                server_hostname=server_hostname,
                session=session,
            )
            try:
                ws.check_pinned_cert()
            except Exception as e:
                ws.close()
                raise e
            return ws


    def create_pinned_default_context(purpose=Purpose.SERVER_AUTH, *, cafile=None, capath=None, cadata=None):
        if not isinstance(purpose, _ASN1Object):
            raise TypeError(purpose)
        if purpose == Purpose.SERVER_AUTH:  # Verify certs and host name in client mode
            context = PinnedSSLContext(PROTOCOL_TLS_CLIENT)
            context.verify_mode, context.check_hostname = CERT_REQUIRED, True
        elif purpose == Purpose.CLIENT_AUTH:
            context = PinnedSSLContext(PROTOCOL_TLS_SERVER)
        else:
            raise ValueError(purpose)
        context.verify_flags |= _ssl.VERIFY_X509_STRICT
        if cafile or capath or cadata:
            context.load_verify_locations(cafile, capath, cadata)
        elif context.verify_mode != CERT_NONE:
            context.load_default_certs(purpose)  # Try loading default system root CA certificates, may fail silently
        if hasattr(context, "keylog_filename"):  # OpenSSL 1.1.1 keylog file
            keylogfile = os.environ.get("SSLKEYLOGFILE")
            if keylogfile and not sys_flags.ignore_environment:
                context.keylog_filename = keylogfile
        return context

    return create_pinned_default_context()
