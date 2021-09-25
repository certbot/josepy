"""Test utilities."""
import os
from typing import Any

import josepy.util
from OpenSSL import crypto
import pkg_resources
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from josepy import ComparableRSAKey, ComparableX509
from josepy.util import ComparableECKey


def vector_path(*names: str) -> str:
    """Path to a test vector."""
    return pkg_resources.resource_filename(
        __name__, os.path.join('testdata', *names))


def load_vector(*names: str) -> bytes:
    """Load contents of a test vector."""
    # luckily, resource_string opens file in binary mode
    return pkg_resources.resource_string(
        __name__, os.path.join('testdata', *names))


def _guess_loader(filename: str, loader_pem: Any, loader_der: Any) -> Any:
    _, ext = os.path.splitext(filename)
    if ext.lower() == '.pem':
        return loader_pem
    elif ext.lower() == '.der':
        return loader_der
    else:  # pragma: no cover
        raise ValueError("Loader could not be recognized based on extension")


def load_cert(*names: str) -> crypto.X509:
    """Load certificate."""
    loader = _guess_loader(
        names[-1], crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1)
    return crypto.load_certificate(loader, load_vector(*names))


def load_comparable_cert(*names: str) -> josepy.util.ComparableX509:
    """Load ComparableX509 cert."""
    return ComparableX509(load_cert(*names))


def load_csr(*names: str) -> crypto.X509Req:
    """Load certificate request."""
    loader = _guess_loader(
        names[-1], crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1)
    return crypto.load_certificate_request(loader, load_vector(*names))


def load_comparable_csr(*names: str) -> josepy.util.ComparableX509:
    """Load ComparableX509 certificate request."""
    return ComparableX509(load_csr(*names))


def load_rsa_private_key(*names: str) -> josepy.util.ComparableRSAKey:
    """Load RSA private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return ComparableRSAKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def load_ec_private_key(*names: str) -> josepy.util.ComparableECKey:
    """Load EC private key."""
    loader = _guess_loader(names[-1], serialization.load_pem_private_key,
                           serialization.load_der_private_key)
    return ComparableECKey(loader(
        load_vector(*names), password=None, backend=default_backend()))


def load_pyopenssl_private_key(*names: str) -> crypto.PKey:
    """Load pyOpenSSL private key."""
    loader = _guess_loader(
        names[-1], crypto.FILETYPE_PEM, crypto.FILETYPE_ASN1)
    return crypto.load_privatekey(loader, load_vector(*names))
