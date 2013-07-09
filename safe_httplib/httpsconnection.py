import httplib
import socket
import ssl

from . import verifiers

class SafeHTTPSConnection(httplib.HTTPSConnection):
    "This class allows communication via SSL."

    default_port = httplib.HTTPS_PORT

    def __init__(self, host, port=None, key_file=None, cert_file=None,
                 strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None, certificate_verifier=verifiers.default,
                 expected_host_name=None):
        httplib.HTTPSConnection.__init__(self, host, port, key_file, cert_file,
            strict, timeout, source_address)
        if expected_host_name is None:
            expected_host_name = host
        self.expected_host_name = expected_host_name
        self.verifier = certificate_verifier
        self.key_file = key_file
        self.cert_file = cert_file

    def connect(self):
        "Connect to a host on a given (SSL) port."

        certificate = ssl.get_server_certificate((self.host, self.port))
        self.verifier.verify(certificate, self.expected_host_name)
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
        self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file)
