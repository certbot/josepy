"""Test utilities.

.. warning:: This module is not part of the public API.

"""
import os

import OpenSSL
import pkg_resources
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from josepy import ComparableRSAKey, ComparableX509
from josepy.util import ComparableRSAKey, ComparableX509, ComparableECKey
from OpenSSL.crypto import PKey, X509, X509Req


def vector_path(*names) -> str:
    """Path to a test vector."""
    return pkg_resources.resource_filename(
        __name__, os.path.join('testdata', *names))


def load_vector(*names) -> bytes:
    """Load contents of a test vector."""
    # luckily, resource_string opens file in binary mode
    return pkg_resources.resource_string(
        __name__, os.path.join('testdata', *names))


def _guess_loader(filename, loader_pem, loader_der):
    _, ext = os.path.splitext(filename)
    if ext.lower() == '.pem':
        return loader_pem
    elif ext.lower() == '.der':
        return loader_der
    else:  # pragma: no cover
        raise ValueError("Loader could not be recognized based on extension")


def load_cert(*names) -> X509:
    """Load certificate."""
    loader = _guess_loader(
        names[-1], OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)
    return OpenSSL.crypto.load_certificate(loader, load_vector(*names))


def load_comparable_cert(*names) -> ComparableX509:
    """Load ComparableX509 cert."""
    return ComparableX509(load_cert(*names))


def load_csr(*names) -> X509Req:
    """Load certificate request."""
    loader = _guess_loader(
        names[-1], OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)
    return OpenSSL.crypto.load_certificate_request(loader, load_vector(*names))


def load_comparable_csr(*names) -> ComparableX509:
    """Load ComparableX509 certificate request."""
    return ComparableX509(load_csr(*names))


def load_rsa_private_key(*names) -> ComparableRSAKey:
    """Load RSA private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return ComparableRSAKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def load_ec_private_key(*names) -> ComparableECKey:
    """Load EC private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return ComparableECKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def load_pyopenssl_private_key(*names) -> PKey:
    """Load pyOpenSSL private key."""
    loader = _guess_loader(
        names[-1], OpenSSL.crypto.FILETYPE_PEM, OpenSSL.crypto.FILETYPE_ASN1)
    return OpenSSL.crypto.load_privatekey(loader, load_vector(*names))
