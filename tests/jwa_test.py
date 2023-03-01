"""Tests for josepy.jwa."""
import sys
import unittest
from unittest import mock

import pytest
import test_util

from josepy import errors

RSA256_KEY = test_util.load_rsa_private_key('rsa256_key.pem')
RSA512_KEY = test_util.load_rsa_private_key('rsa512_key.pem')
RSA1024_KEY = test_util.load_rsa_private_key('rsa1024_key.pem')
EC_P256_KEY = test_util.load_ec_private_key('ec_p256_key.pem')
EC_P384_KEY = test_util.load_ec_private_key('ec_p384_key.pem')
EC_P521_KEY = test_util.load_ec_private_key('ec_p521_key.pem')


class JWASignatureTest(unittest.TestCase):
    """Tests for josepy.jwa.JWASignature."""

    def setUp(self):
        from josepy.jwa import JWASignature

        class MockSig(JWASignature):
            def sign(self, key, msg):
                raise NotImplementedError()  # pragma: no cover

            def verify(self, key, msg, sig):
                raise NotImplementedError()  # pragma: no cover

        self.Sig1 = MockSig('Sig1')
        self.Sig2 = MockSig('Sig2')

    def test_eq(self):
        assert self.Sig1 == self.Sig1

    def test_ne(self):
        assert self.Sig1 != self.Sig2

    def test_ne_other_type(self):
        assert self.Sig1 != 5

    def test_repr(self):
        assert 'Sig1' == repr(self.Sig1)
        assert 'Sig2' == repr(self.Sig2)

    def test_to_partial_json(self):
        assert self.Sig1.to_partial_json() == 'Sig1'
        assert self.Sig2.to_partial_json() == 'Sig2'

    def test_from_json(self):
        from josepy.jwa import RS256, JWASignature
        assert JWASignature.from_json('RS256') is RS256


class JWAHSTest(unittest.TestCase):

    def test_it(self):
        from josepy.jwa import HS256
        sig = (
            b"\xceR\xea\xcd\x94\xab\xcf\xfb\xe0\xacA.:\x1a'\x08i\xe2\xc4"
            b"\r\x85+\x0e\x85\xaeUZ\xd4\xb3\x97zO"
        )
        assert HS256.sign(b'some key', b'foo') == sig
        assert HS256.verify(b'some key', b'foo', sig) is True
        assert HS256.verify(b'some key', b'foo', sig + b'!') is False


class JWARSTest(unittest.TestCase):

    def test_sign_no_private_part(self):
        from josepy.jwa import RS256
        with pytest.raises(errors.Error):
            RS256.sign(RSA512_KEY.public_key(), b'foo')

    def test_sign_key_too_small(self):
        from josepy.jwa import PS256, RS256
        with pytest.raises(errors.Error):
            RS256.sign(RSA256_KEY, b'foo')
        with pytest.raises(errors.Error):
            PS256.sign(RSA256_KEY, b'foo')

    def test_rs(self):
        from josepy.jwa import RS256
        sig = (
            b'|\xc6\xb2\xa4\xab(\x87\x99\xfa*:\xea\xf8\xa0N&}\x9f\x0f\xc0O'
            b'\xc6t\xa3\xe6\xfa\xbb"\x15Y\x80Y\xe0\x81\xb8\x88)\xba\x0c\x9c'
            b'\xa4\x99\x1e\x19&\xd8\xc7\x99S\x97\xfc\x85\x0cOV\xe6\x07\x99'
            b'\xd2\xb9.>}\xfd'
        )
        assert RS256.sign(RSA512_KEY, b'foo') == sig
        assert RS256.verify(RSA512_KEY.public_key(), b'foo', sig) is True
        assert RS256.verify(
            RSA512_KEY.public_key(), b'foo', sig + b'!') is False

    def test_ps(self):
        from josepy.jwa import PS256
        sig = PS256.sign(RSA1024_KEY, b'foo')
        assert PS256.verify(RSA1024_KEY.public_key(), b'foo', sig) is True
        assert PS256.verify(
            RSA1024_KEY.public_key(), b'foo', sig + b'!') is False

    def test_sign_new_api(self):
        from josepy.jwa import RS256
        key = mock.MagicMock()
        RS256.sign(key, "message")
        assert key.sign.called is True

    def test_verify_new_api(self):
        from josepy.jwa import RS256
        key = mock.MagicMock()
        RS256.verify(key, "message", "signature")
        assert key.verify.called is True


class JWAECTest(unittest.TestCase):

    def test_sign_no_private_part(self):
        from josepy.jwa import ES256
        with pytest.raises(errors.Error):
            ES256.sign(EC_P256_KEY.public_key(), b'foo')

    def test_es256_sign_and_verify(self):
        from josepy.jwa import ES256
        message = b'foo'
        signature = ES256.sign(EC_P256_KEY, message)
        assert ES256.verify(EC_P256_KEY.public_key(), message, signature) is True

    def test_es384_sign_and_verify(self):
        from josepy.jwa import ES384
        message = b'foo'
        signature = ES384.sign(EC_P384_KEY, message)
        assert ES384.verify(EC_P384_KEY.public_key(), message, signature) is True

    def test_verify_with_wrong_jwa(self):
        from josepy.jwa import ES256, ES384
        message = b'foo'
        signature = ES256.sign(EC_P256_KEY, message)
        assert ES384.verify(EC_P384_KEY.public_key(), message, signature) is False

    def test_verify_with_different_key(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import ec

        from josepy.jwa import ES256

        message = b'foo'
        signature = ES256.sign(EC_P256_KEY, message)
        different_key = ec.generate_private_key(ec.SECP256R1, default_backend())
        assert ES256.verify(different_key.public_key(), message, signature) is False

    def test_sign_new_api(self):
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

        from josepy.jwa import ES256
        key = mock.MagicMock(curve=SECP256R1())
        with mock.patch("josepy.jwa.decode_dss_signature") as decode_patch:
            decode_patch.return_value = (0, 0)
            ES256.sign(key, "message")
        assert key.sign.called is True

    def test_verify_new_api(self):
        import math

        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

        from josepy.jwa import ES256
        key = mock.MagicMock(key_size=256, curve=SECP256R1())
        ES256.verify(key, "message", b'\x00' * math.ceil(key.key_size / 8) * 2)
        assert key.verify.called is True

    def test_signature_size(self):
        from josepy.jwa import ES512
        from josepy.jwk import JWK
        key = JWK.from_json(
            {
                'd': 'Af9KP6DqLRbtit6NS_LRIaCP_-NdC5l5R2ugbILdfpv6dS9R4wUPNxiGw'
                     '-vVWumA56Yo1oBnEm8ZdR4W-u1lPHw5',
                'x': 'AD4i4STyJ07iZJkHkpKEOuICpn6IHknzwAlrf-1w1a5dqOsRe30EECSN4vFxae'
                     'AmtdBSCKBwCq7h1q4bPgMrMUvF',
                'y': 'AHAlXxrabjcx_yBxGObnm_DkEQMJK1E69OHY3x3VxF5VXoKc93CG4GLoaPvphZQv'
                     'Znt5EfExQoPktwOMIVhBHaFR',
                'crv': 'P-521',
                'kty': 'EC'
            })
        with mock.patch("josepy.jwa.decode_dss_signature") as decode_patch:
            decode_patch.return_value = (0, 0)
            sig = ES512.sign(key.key, b"test")
            assert len(sig) == 2 * 66


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
