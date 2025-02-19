import os
from hashlib import sha256
from ssl import (
    CERT_NONE,
    CERT_REQUIRED,
    PROTOCOL_TLS_CLIENT,
    PROTOCOL_TLS_SERVER,
    Purpose,
    SSLCertVerificationError,
    SSLContext,
    SSLSocket,
    _ASN1Object,
    _ssl,
)
from sys import flags as sys_flags


def make_pinned_ssl_context(pinned_sha_256):
    """
    Tested with `python-version: [3.8, 3.9, 3.10, 3.11, 3.12, 3.13]`
    """
    # TODO Document
    # TODO Explain can be found here
    # TODO Copy
    class PinnedSSLSocket(SSLSocket):
        def check_pinned_cert(self):
            der_cert_bin = self.getpeercert(True)
            if sha256(der_cert_bin).hexdigest() != pinned_sha_256:
                raise SSLCertVerificationError("Incorrect certificate checksum")

        def do_handshake(self, *args, **kwargs):
            r = super().do_handshake(*args, **kwargs)
            self.check_pinned_cert()
            return r

    class PinnedSSLContext(SSLContext):
        sslsocket_class = PinnedSSLSocket

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
