import cStringIO as StringIO
import subprocess
import tempfile

import OpenSSL


class InvalidCertificateError(Exception):
    def __init__(self, certificate, hostname):
        self.certificate = certificate
        self.hostname = hostname

    def __repr__(self):
        return '%s(%s, %r)' % (
            self.__class__.__name__,
            '[certificate]',
            self.hostname
        )

    def __str__(self):
        return repr(self)


class ExpiredCertificateError(InvalidCertificateError):
    pass


class _BaseVerifier(object):
    _repr_keys = ('check_host_name',)

    def __init__(self, check_host_name=True):
        self.check_host_name = check_host_name

    def verify(self, certificate, expected_host_name):
        raise NotImplementedError()

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__,
                ', '.join(('%s=%s' % (key, getattr(self, key))) for key in self._repr_keys))


class HugelyInsecureVerifier(_BaseVerifier):
    """A Verifier that doesn't actually verify the certificate. Do not use."""

    def verify(self, certificate, expected_host_name):
        pass


class OSXVerifier(_BaseVerifier):
    """A Verifier that uses the `security` utility to verify certificates.

    This results in a shell call, which is very slow. But it is probably secure!
    """

    def verify(self, certificate, expected_host_name):
        with tempfile.NamedTemporaryFile() as f:
            f.write(certificate)
            f.flush()
            with open('/dev/null', 'w') as devnull:
                command = ['/usr/bin/security',
                    'verify-cert',
                    '-c', f.name,
                    '-p', 'ssl',
                    '-L']
                if self.check_host_name:
                    command += ['-s', expected_host_name]
                verified_return = subprocess.call(command, shell=False, stdout=devnull, stderr=devnull)
                if verified_return != 0:
                    raise InvalidCertificateError(certificate, expected_host_name)


class CABundleVerifier(_BaseVerifier):
    """A Verifier that uses a static CA bundle."""

    def verify(self, certificate, expected_host_name):
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
        if cert.has_expired() != 0:
            raise ExpiredCertificateError(certificate, expected_host_name)
        import pdb
        pdb.set_trace()
        print cert


default = CABundleVerifier()
