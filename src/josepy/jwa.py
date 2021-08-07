"""JSON Web Algorithms.

https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-40

"""
import abc
import logging
from typing import Dict, Type, Union

import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import ec, x25519, x448
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric import ed448
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from josepy import errors, interfaces, jwk

from collections.abc import Hashable

logger = logging.getLogger(__name__)


class JWA(interfaces.JSONDeSerializable):  # pylint: disable=abstract-method
    # pylint: disable=too-few-public-methods
    # for some reason disable=abstract-method has to be on the line
    # above...
    """JSON Web Algorithm."""


class JWASignature(JWA, Hashable):
    """Base class for JSON Web Signature Algorithms."""
    SIGNATURES: Dict[str, Type] = {}

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        if not isinstance(other, JWASignature):
            return NotImplemented
        return self.name == other.name

    def __hash__(self):
        return hash((self.__class__, self.name))

    @classmethod
    def register(cls, signature_cls):
        """Register class for JSON deserialization."""
        cls.SIGNATURES[signature_cls.name] = signature_cls
        return signature_cls

    def to_partial_json(self):
        return self.name

    @classmethod
    def from_json(cls, jobj):
        return cls.SIGNATURES[jobj]

    @abc.abstractmethod
    def sign(self, key, msg):  # pragma: no cover
        """Sign the ``msg`` using ``key``."""
        raise NotImplementedError()

    @abc.abstractmethod
    def verify(self, key, msg, sig):  # pragma: no cover
        """Verify the ``msg`` and ``sig`` using ``key``."""
        raise NotImplementedError()

    def __repr__(self):
        return self.name


class _JWAHS(JWASignature):
    kty = jwk.JWKOct

    def __init__(self, name, hash_):
        super().__init__(name)
        self.hash = hash_()

    def sign(self, key, msg):
        signer = hmac.HMAC(key, self.hash, backend=default_backend())
        signer.update(msg)
        return signer.finalize()

    def verify(self, key, msg, sig):
        verifier = hmac.HMAC(key, self.hash, backend=default_backend())
        verifier.update(msg)
        try:
            verifier.verify(sig)
        except cryptography.exceptions.InvalidSignature as error:
            logger.debug(error, exc_info=True)
            return False
        else:
            return True


class _JWARSA:
    kty = jwk.JWKRSA
    padding = NotImplemented
    hash = NotImplemented

    def sign(self, key, msg):
        """Sign the ``msg`` using ``key``."""
        # If cryptography library supports new style api (v1.4 and later)
        new_api = hasattr(key, "sign")
        try:
            if new_api:
                return key.sign(msg, self.padding, self.hash)
            signer = key.signer(self.padding, self.hash)
        except AttributeError as error:
            logger.debug(error, exc_info=True)
            raise errors.Error("Public key cannot be used for signing")
        except ValueError as error:  # digest too large
            logger.debug(error, exc_info=True)
            raise errors.Error(str(error))
        signer.update(msg)
        try:
            return signer.finalize()
        except ValueError as error:
            logger.debug(error, exc_info=True)
            raise errors.Error(str(error))

    def verify(self, key, msg, sig):
        """Verify the ``msg` and ``sig`` using ``key``."""
        # If cryptography library supports new style api (v1.4 and later)
        new_api = hasattr(key, "verify")
        if not new_api:
            verifier = key.verifier(sig, self.padding, self.hash)
            verifier.update(msg)
        try:
            if new_api:
                key.verify(sig, msg, self.padding, self.hash)
            else:
                verifier.verify()
        except cryptography.exceptions.InvalidSignature as error:
            logger.debug(error, exc_info=True)
            return False
        else:
            return True


class _JWARS(_JWARSA, JWASignature):

    def __init__(self, name, hash_):
        super().__init__(name)
        self.padding = padding.PKCS1v15()
        self.hash = hash_()


class _JWAPS(_JWARSA, JWASignature):

    def __init__(self, name, hash_):
        super().__init__(name)
        self.padding = padding.PSS(
            mgf=padding.MGF1(hash_()),
            salt_length=padding.PSS.MAX_LENGTH)
        self.hash = hash_()


class _JWAEC(JWASignature):
    kty = jwk.JWKEC

    def __init__(self, name, hash_):
        super().__init__(name)
        self.hash = hash_()

    def sign(self, key, msg):
        """Sign the ``msg`` using ``key``."""
        sig = self._sign(key, msg)
        dr, ds = decode_dss_signature(sig)
        length = jwk.JWKEC.expected_length_for_curve(key.curve)
        return (dr.to_bytes(length=length, byteorder='big') +
                ds.to_bytes(length=length, byteorder='big'))

    def _sign(self, key, msg):
        # If cryptography library supports new style api (v1.4 and later)
        new_api = hasattr(key, 'sign')
        try:
            if new_api:
                return key.sign(msg, ec.ECDSA(self.hash))
            signer = key.signer(ec.ECDSA(self.hash))
        except AttributeError as error:
            logger.debug(error, exc_info=True)
            raise errors.Error('Public key cannot be used for signing')
        except ValueError as error:  # digest too large
            logger.debug(error, exc_info=True)
            raise errors.Error(str(error))
        signer.update(msg)
        try:
            return signer.finalize()
        except ValueError as error:
            logger.debug(error, exc_info=True)
            raise errors.Error(str(error))

    def verify(self, key, msg, sig):
        """Verify the ``msg` and ``sig`` using ``key``."""
        rlen = jwk.JWKEC.expected_length_for_curve(key.curve)
        if len(sig) != 2 * rlen:
            # Format error - rfc7518 - 3.4 … MUST NOT be shortened to omit any leading zero octets
            return False
        asn1sig = encode_dss_signature(
            int.from_bytes(sig[0:rlen], byteorder='big'),
            int.from_bytes(sig[rlen:], byteorder='big')
        )
        return self._verify(key, msg, asn1sig)

    def _verify(self, key, msg, asn1sig):
        # If cryptography library supports new style api (v1.4 and later)
        new_api = hasattr(key, 'verify')
        if not new_api:
            verifier = key.verifier(asn1sig, ec.ECDSA(self.hash))
            verifier.update(msg)
        try:
            if new_api:
                key.verify(asn1sig, msg, ec.ECDSA(self.hash))
            else:
                verifier.verify()
        except cryptography.exceptions.InvalidSignature as error:
            logger.debug(error, exc_info=True)
            return False
        else:
            return True


class _JWAOKP(JWASignature):
    kty = jwk.JWKOKP

    def __init__(self, name, hash_):
        super().__init__(name)
        self.hash = hash_()

    def sign(self, key: Union[
        ed25519.Ed25519PrivateKey,
        ed448.Ed448PrivateKey,
        x25519.X25519PrivateKey,
        x448.X448PrivateKey,
    ], msg: bytes):
        return key.sign(msg)

    def verify(self, key: Union[
        ed25519.Ed25519PublicKey,
        ed448.Ed448PublicKey,
        x25519.X25519PrivateKey,
        x448.X448PrivateKey,
    ], msg: bytes, sig: bytes):
        try:
            key.verify(signature=sig, data=msg)
        except cryptography.exceptions.InvalidSignature as error:
            logger.debug(error, exc_info=True)
            return False
        else:
            return True


#: HMAC using SHA-256
HS256 = JWASignature.register(_JWAHS('HS256', hashes.SHA256))
#: HMAC using SHA-384
HS384 = JWASignature.register(_JWAHS('HS384', hashes.SHA384))
#: HMAC using SHA-512
HS512 = JWASignature.register(_JWAHS('HS512', hashes.SHA512))

#: RSASSA-PKCS-v1_5 using SHA-256
RS256 = JWASignature.register(_JWARS('RS256', hashes.SHA256))
#: RSASSA-PKCS-v1_5 using SHA-384
RS384 = JWASignature.register(_JWARS('RS384', hashes.SHA384))
#: RSASSA-PKCS-v1_5 using SHA-512
RS512 = JWASignature.register(_JWARS('RS512', hashes.SHA512))

#: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
PS256 = JWASignature.register(_JWAPS('PS256', hashes.SHA256))
#: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
PS384 = JWASignature.register(_JWAPS('PS384', hashes.SHA384))
#: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
PS512 = JWASignature.register(_JWAPS('PS512', hashes.SHA512))

#: ECDSA using P-256 and SHA-256
ES256 = JWASignature.register(_JWAEC('ES256', hashes.SHA256))
#: ECDSA using P-384 and SHA-384
ES384 = JWASignature.register(_JWAEC('ES384', hashes.SHA384))
#: ECDSA using P-521 and SHA-512
ES512 = JWASignature.register(_JWAEC('ES512', hashes.SHA512))

#: Ed25519 uses SHA512
ES25519 = JWASignature.register(_JWAOKP('ES25519', hashes.SHA512))

#: Ed448 uses SHA3/SHAKE256
ES448 = JWASignature.register(_JWAOKP('ES448', hashes.SHAKE256))

#: X25519

#: X448
