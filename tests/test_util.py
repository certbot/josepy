"""Test utilities."""

import atexit
import contextlib
import importlib.resources
import os
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import josepy.util
from josepy import ComparableRSAKey
from josepy.util import ComparableECKey

TESTDATA = importlib.resources.files("testdata")


def vector_path(*names: str) -> str:
    """Path to a test vector."""
    # This code is based on the recommendation at
    # https://web.archive.org/web/20230131043552/https://importlib-resources.readthedocs.io/en/latest/migration.html#pkg-resources-resource-filename.
    file_manager = contextlib.ExitStack()
    atexit.register(file_manager.close)
    ref = TESTDATA.joinpath(*names)
    # We convert the value to str here because some of the calling code doesn't
    # work with pathlib objects.
    return str(file_manager.enter_context(importlib.resources.as_file(ref)))


def load_vector(*names: str) -> bytes:
    """Load contents of a test vector."""
    return TESTDATA.joinpath(*names).read_bytes()


def _guess_loader(filename: str, loader_pem: Any, loader_der: Any) -> Any:
    _, ext = os.path.splitext(filename)
    if ext.lower() == ".pem":
        return loader_pem
    elif ext.lower() == ".der":
        return loader_der
    else:  # pragma: no cover
        raise ValueError("Loader could not be recognized based on extension")


def load_cert(*names: str) -> x509.Certificate:
    """Load certificate."""
    loader = _guess_loader(
        names[-1], x509.load_pem_x509_certificate, x509.load_der_x509_certificate
    )
    return loader(load_vector(*names))


def load_csr(*names: str) -> x509.CertificateSigningRequest:
    """Load certificate request."""
    loader = _guess_loader(names[-1], x509.load_pem_x509_csr, x509.load_der_x509_csr)
    return loader(load_vector(*names))


def load_rsa_private_key(*names: str) -> josepy.util.ComparableRSAKey:
    """Load RSA private key."""
    loader = _guess_loader(
        names[-1], serialization.load_pem_private_key, serialization.load_der_private_key
    )
    return ComparableRSAKey(loader(load_vector(*names), password=None, backend=default_backend()))


def load_ec_private_key(*names: str) -> josepy.util.ComparableECKey:
    """Load EC private key."""
    loader = _guess_loader(
        names[-1], serialization.load_pem_private_key, serialization.load_der_private_key
    )
    return ComparableECKey(loader(load_vector(*names), password=None, backend=default_backend()))
