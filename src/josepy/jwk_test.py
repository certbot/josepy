"""Tests for josepy.jwk."""
import binascii
import unittest

from josepy import errors, json_util, test_util, util

DSA_PEM = test_util.load_vector('dsa512_key.pem')
RSA256_KEY = test_util.load_rsa_private_key('rsa256_key.pem')
RSA512_KEY = test_util.load_rsa_private_key('rsa512_key.pem')
EC_P256_KEY = test_util.load_ec_private_key('ec_p256_key.pem')
EC_P384_KEY = test_util.load_ec_private_key('ec_p384_key.pem')
EC_P521_KEY = test_util.load_ec_private_key('ec_p521_key.pem')
Ed25519_KEY = test_util.load_ec_private_key('ed25519_key.pem')
Ed448_KEY = test_util.load_ec_private_key('ed448_key.pem')
X25519_KEY = test_util.load_ec_private_key('x25519_key.pem')
X448_KEY = test_util.load_ec_private_key('x448_key.pem')


class JWKTest(unittest.TestCase):
    """Tests for josepy.jwk.JWK."""

    def test_load(self):
        from josepy.jwk import JWK
        self.assertRaises(errors.Error, JWK.load, DSA_PEM)

    def test_load_subclass_wrong_type(self):
        from josepy.jwk import JWKRSA
        self.assertRaises(errors.Error, JWKRSA.load, DSA_PEM)


class JWKTestBaseMixin:
    """Mixin test for JWK subclass tests."""

    thumbprint: bytes = NotImplemented

    def test_thumbprint_private(self):
        self.assertEqual(self.thumbprint, self.jwk.thumbprint())

    def test_thumbprint_public(self):
        self.assertEqual(self.thumbprint, self.jwk.public_key().thumbprint())


class JWKOctTest(unittest.TestCase, JWKTestBaseMixin):
    """Tests for josepy.jwk.JWKOct."""

    thumbprint = (b"\xf3\xe7\xbe\xa8`\xd2\xdap\xe9}\x9c\xce>"
                  b"\xd0\xfcI\xbe\xcd\x92'\xd4o\x0e\xf41\xea"
                  b"\x8e(\x8a\xb2i\x1c")

    def setUp(self):
        from josepy.jwk import JWKOct
        self.jwk = JWKOct(key=b'foo')
        self.jobj = {'kty': 'oct', 'k': json_util.encode_b64jose(b'foo')}

    def test_to_partial_json(self):
        self.assertEqual(self.jwk.to_partial_json(), self.jobj)

    def test_from_json(self):
        from josepy.jwk import JWKOct
        self.assertEqual(self.jwk, JWKOct.from_json(self.jobj))

    def test_from_json_hashable(self):
        from josepy.jwk import JWKOct
        hash(JWKOct.from_json(self.jobj))

    def test_load(self):
        from josepy.jwk import JWKOct
        self.assertEqual(self.jwk, JWKOct.load(b'foo'))

    def test_public_key(self):
        self.assertIs(self.jwk.public_key(), self.jwk)


class JWKRSATest(unittest.TestCase, JWKTestBaseMixin):
    """Tests for josepy.jwk.JWKRSA."""
    # pylint: disable=too-many-instance-attributes

    thumbprint = (b'\x83K\xdc#3\x98\xca\x98\xed\xcb\x80\x80<\x0c'
                  b'\xf0\x95\xb9H\xb2*l\xbd$\xe5&|O\x91\xd4 \xb0Y')

    def setUp(self):
        from josepy.jwk import JWKRSA
        self.jwk256 = JWKRSA(key=RSA256_KEY.public_key())
        self.jwk256json = {
            'kty': 'RSA',
            'e': 'AQAB',
            'n': 'm2Fylv-Uz7trgTW8EBHP3FQSMeZs2GNQ6VRo1sIVJEk',
        }
        # pylint: disable=protected-access
        self.jwk256_not_comparable = JWKRSA(
            key=RSA256_KEY.public_key()._wrapped)
        self.jwk512 = JWKRSA(key=RSA512_KEY.public_key())
        self.jwk512json = {
            'kty': 'RSA',
            'e': 'AQAB',
            'n': 'rHVztFHtH92ucFJD_N_HW9AsdRsUuHUBBBDlHwNlRd3fp5'
                 '80rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3C5Q',
        }
        self.private = JWKRSA(key=RSA256_KEY)
        self.private_json_small = self.jwk256json.copy()
        self.private_json_small['d'] = (
            'lPQED_EPTV0UIBfNI3KP2d9Jlrc2mrMllmf946bu-CE')
        self.private_json = self.jwk256json.copy()
        self.private_json.update({
            'd': 'lPQED_EPTV0UIBfNI3KP2d9Jlrc2mrMllmf946bu-CE',
            'p': 'zUVNZn4lLLBD1R6NE8TKNQ',
            'q': 'wcfKfc7kl5jfqXArCRSURQ',
            'dp': 'CWJFq43QvT5Bm5iN8n1okQ',
            'dq': 'bHh2u7etM8LKKCF2pY2UdQ',
            'qi': 'oi45cEkbVoJjAbnQpFY87Q',
        })
        self.jwk = self.private

    def test_init_auto_comparable(self):
        self.assertIsInstance(self.jwk256_not_comparable.key, util.ComparableRSAKey)
        self.assertEqual(self.jwk256, self.jwk256_not_comparable)

    def test_encode_param_zero(self):
        from josepy.jwk import JWKRSA
        # pylint: disable=protected-access
        # TODO: move encode/decode _param to separate class
        self.assertEqual('AA', JWKRSA._encode_param(0))

    def test_equals(self):
        self.assertEqual(self.jwk256, self.jwk256)
        self.assertEqual(self.jwk512, self.jwk512)

    def test_not_equals(self):
        self.assertNotEqual(self.jwk256, self.jwk512)
        self.assertNotEqual(self.jwk512, self.jwk256)

    def test_load(self):
        from josepy.jwk import JWKRSA
        self.assertEqual(self.private, JWKRSA.load(
            test_util.load_vector('rsa256_key.pem')))

    def test_public_key(self):
        self.assertEqual(self.jwk256, self.private.public_key())

    def test_to_partial_json(self):
        self.assertEqual(self.jwk256.to_partial_json(), self.jwk256json)
        self.assertEqual(self.jwk512.to_partial_json(), self.jwk512json)
        self.assertEqual(self.private.to_partial_json(), self.private_json)

    def test_from_json(self):
        from josepy.jwk import JWK
        self.assertEqual(
            self.jwk256, JWK.from_json(self.jwk256json))
        self.assertEqual(
            self.jwk512, JWK.from_json(self.jwk512json))
        self.assertEqual(self.private, JWK.from_json(self.private_json))

    def test_from_json_private_small(self):
        from josepy.jwk import JWK
        self.assertEqual(self.private, JWK.from_json(self.private_json_small))

    def test_from_json_missing_one_additional(self):
        from josepy.jwk import JWK
        del self.private_json['q']
        self.assertRaises(errors.Error, JWK.from_json, self.private_json)

    def test_from_json_hashable(self):
        from josepy.jwk import JWK
        hash(JWK.from_json(self.jwk256json))

    def test_from_json_non_schema_errors(self):
        # valid against schema, but still failing
        from josepy.jwk import JWK
        self.assertRaises(errors.DeserializationError, JWK.from_json,
                          {'kty': 'RSA', 'e': 'AQAB', 'n': ''})
        self.assertRaises(errors.DeserializationError, JWK.from_json,
                          {'kty': 'RSA', 'e': 'AQAB', 'n': '1'})

    def test_thumbprint_go_jose(self):
        # https://github.com/square/go-jose/blob/4ddd71883fa547d37fbf598071f04512d8bafee3/jwk.go#L155
        # https://github.com/square/go-jose/blob/4ddd71883fa547d37fbf598071f04512d8bafee3/jwk_test.go#L331-L344
        # https://github.com/square/go-jose/blob/4ddd71883fa547d37fbf598071f04512d8bafee3/jwk_test.go#L384
        from josepy.jwk import JWKRSA
        key = JWKRSA.json_loads("""{
    "kty": "RSA",
    "kid": "bilbo.baggins@hobbiton.example",
    "use": "sig",
    "n": "n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqVwGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuCLqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5gHdrNP5zw",
    "e": "AQAB"
}""")
        self.assertEqual(
            binascii.hexlify(key.thumbprint()),
            b"f63838e96077ad1fc01c3f8405774dedc0641f558ebb4b40dccf5f9b6d66a932")


class JWKECTest(unittest.TestCase, JWKTestBaseMixin):
    """Tests for josepy.jwk.JWKEC."""
    # pylint: disable=too-many-instance-attributes

    thumbprint = (b'\x06\xceL\x1b\xa8\x8d\x86\x1flF\x99J\x8b\xe0$\t\xbbj'
                  b'\xd8\xf6O\x1ed\xdeR\x8f\x97\xff\xf6\xa2\x86\xd3')

    def setUp(self):
        from josepy.jwk import JWKEC
        self.jwk256 = JWKEC(key=EC_P256_KEY.public_key())
        self.jwk384 = JWKEC(key=EC_P384_KEY.public_key())
        self.jwk521 = JWKEC(key=EC_P521_KEY.public_key())
        self.jwk256_not_comparable = JWKEC(key=EC_P256_KEY.public_key()._wrapped)
        self.jwk256json = {
            'kty': 'EC',
            'crv': 'P-256',
            'x': 'jjQtV-fA7J_tK8dPzYq7jRPNjF8r5p6LW2R25S2Gw5U',
            'y': 'EPAw8_8z7PYKsHH6hlGSlsWxFoFl7-0vM0QRGbmnvCc',
        }
        self.jwk384json = {
            'kty': 'EC',
            'crv': 'P-384',
            'x': 'tIhpNtEXkadUbrY84rYGgApFM1X_3l3EWQRuOP1IWtxlTftrZQwneJZF0k0eRn00',
            'y': 'KW2Gp-TThDXmZ-9MJPnD8hv-X130SVvfZRl1a04HPVwIbvLe87mvA_iuOa-myUyv',
        }
        self.jwk521json = {
            'kty': 'EC',
            'crv': 'P-521',
            'x': 'AFkdl6cKzBmP18U8fffpP4IZN2eED45hDcwRPl5ZeClwHcLtnMBMuWYFFO_Nzm6DL2MhpN0zI2bcMLJd95aY2tPs',
            'y': 'AYvZq3wByjt7nQd8nYMqhFNCL3j_-U6GPWZet1hYBY_XZHrC4yIV0R4JnssRAY9eqc1EElpCc4hziis1jiV1iR4W',
        }
        self.private = JWKEC(key=EC_P256_KEY)
        self.private_json = {
            'd': 'xReNQBKqqTthG8oTmBdhp4EQYImSK1dVqfa2yyMn2rc',
            'x': 'jjQtV-fA7J_tK8dPzYq7jRPNjF8r5p6LW2R25S2Gw5U',
            'y': 'EPAw8_8z7PYKsHH6hlGSlsWxFoFl7-0vM0QRGbmnvCc',
            'crv': 'P-256',
            'kty': 'EC'}
        self.jwk = self.private

    def test_init_auto_comparable(self):
        self.assertIsInstance(self.jwk256_not_comparable.key, util.ComparableECKey)
        self.assertEqual(self.jwk256, self.jwk256_not_comparable)

    def test_encode_param_zero(self):
        from josepy.jwk import JWKEC
        # pylint: disable=protected-access
        # TODO: move encode/decode _param to separate class
        self.assertEqual('AA', JWKEC._encode_param(0, 1))

    def test_equals(self):
        self.assertEqual(self.jwk256, self.jwk256)
        self.assertEqual(self.jwk384, self.jwk384)
        self.assertEqual(self.jwk521, self.jwk521)

    def test_not_equals(self):
        self.assertNotEqual(self.jwk256, self.jwk384)
        self.assertNotEqual(self.jwk256, self.jwk521)
        self.assertNotEqual(self.jwk384, self.jwk256)
        self.assertNotEqual(self.jwk384, self.jwk521)
        self.assertNotEqual(self.jwk521, self.jwk256)
        self.assertNotEqual(self.jwk521, self.jwk384)

    def test_load(self):
        from josepy.jwk import JWKEC
        self.assertEqual(self.private, JWKEC.load(
            test_util.load_vector('ec_p256_key.pem')))

    def test_public_key(self):
        self.assertEqual(self.jwk256, self.private.public_key())

    def test_to_partial_json(self):
        self.assertEqual(self.jwk256.to_partial_json(), self.jwk256json)
        self.assertEqual(self.jwk384.to_partial_json(), self.jwk384json)
        self.assertEqual(self.jwk521.to_partial_json(), self.jwk521json)
        self.assertEqual(self.private.to_partial_json(), self.private_json)

    def test_from_json(self):
        from josepy.jwk import JWK
        self.assertEqual(
            self.jwk256, JWK.from_json(self.jwk256json))
        self.assertEqual(
            self.jwk384, JWK.from_json(self.jwk384json))
        self.assertEqual(
            self.jwk521, JWK.from_json(self.jwk521json))
        self.assertEqual(
            self.private, JWK.from_json(self.private_json))

    def test_from_json_missing_x_coordinate(self):
        from josepy.jwk import JWK
        del self.private_json['x']
        self.assertRaises(KeyError, JWK.from_json, self.private_json)

    def test_from_json_missing_y_coordinate(self):
        from josepy.jwk import JWK
        del self.private_json['y']
        self.assertRaises(KeyError, JWK.from_json, self.private_json)

    def test_from_json_hashable(self):
        from josepy.jwk import JWK
        hash(JWK.from_json(self.jwk256json))

    def test_from_json_non_schema_errors(self):
        # valid against schema, but still failing
        from josepy.jwk import JWK
        self.assertRaises(errors.DeserializationError, JWK.from_json,
                          {'kty': 'EC', 'crv': 'P-256', 'x': 'AQAB',
                           'y': 'm2Fylv-Uz7trgTW8EBHP3FQSMeZs2GNQ6VRo1sIVJEk'})
        self.assertRaises(errors.DeserializationError, JWK.from_json,
                          {'kty': 'EC', 'crv': 'P-256', 'x': 'jjQtV-fA7J_tK8dPzYq7jRPNjF8r5p6LW2R25S2Gw5U', 'y': '1'})

    def test_unknown_crv_name(self):
        from josepy.jwk import JWK
        self.assertRaises(errors.DeserializationError, JWK.from_json,
                          {'kty': 'EC',
                           'crv': 'P-255',
                           'x': 'jjQtV-fA7J_tK8dPzYq7jRPNjF8r5p6LW2R25S2Gw5U',
                           'y': 'EPAw8_8z7PYKsHH6hlGSlsWxFoFl7-0vM0QRGbmnvCc'})

    def test_encode_y_leading_zero_p256(self):
        from josepy.jwk import JWKEC, JWK
        import josepy
        data = b"""-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICZ7LCI99Na2KZ/Fq8JmJROakGJ5+J7rHiGSPoO36kOAoAoGCCqGSM49
AwEHoUQDQgAEGS5RvStca15z2FEanCM3juoX7tE/LB7iD44GWawGE40APAl/iZuH
31wQfst4glTZpxkpEI/MzNZHjiYnqrGeSw==
-----END EC PRIVATE KEY-----"""
        key = JWKEC.load(data)
        data = key.to_partial_json()
        y = josepy.json_util.decode_b64jose(data['y'])
        self.assertEqual(y[0], 0)
        self.assertEqual(len(y), 32)
        JWK.from_json(data)


class JWKOKPTest(unittest.TestCase):
    """Tests for josepy.jwk.JWKOKP."""
    # pylint: disable=too-many-instance-attributes

    # TODO: write the thumbprint
    thumbprint = (
        b'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k'
    )

    def setUp(self):
        from josepy.jwk import JWKOKP
        self.ed25519_key = JWKOKP(key=Ed25519_KEY.public_key())
        self.ed448_key = JWKOKP(key=Ed448_KEY.public_key())
        self.x25519_key = JWKOKP(key=X25519_KEY.public_key())
        self.x448_key = JWKOKP(key=X448_KEY.public_key())
        self.private = self.x448_key
        self.jwk = self.private
        # Test vectors taken from RFC 8037, A.2
        self.jwked25519json = {
            'kty': 'OKP',
            'crv': 'Ed25519',
            'x': '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
        }
        self.jwked448json = {
            'kty': 'OKP',
            'crv': 'Ed448',
            'x':
                "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
                "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
        }
        # Test vectors taken from
        # https://datatracker.ietf.org/doc/html/rfc7748#section-6.1
        self.jwkx25519json = {
            'kty': 'OKP',
            'crv': 'X25519',
            'x': '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
        }
        self.jwkx448json = {
            'kty': 'OKP',
            'crv': 'X448',
            'x': 'jjQtV-fA7J_tK8dPzYq7jRPNjF8r5p6LW2R25S2Gw5U',
        }

    def test_encode_ed448(self):
        from josepy.jwk import JWKOKP
        data = b"""-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOfqsAFWdop10FFPW7Ha2tx2AZh0Ii+jfL2wFXU/dY/fe
iU7/vrGmQ+ux26NkgzfploOHZjEmltLJ9w==
-----END PRIVATE KEY-----"""
        key = JWKOKP.load(data)
        partial = key.to_partial_json()
        self.assertEqual(partial['crv'], 'Ed448')

    def test_encode_ed25519(self):
        import josepy
        from josepy.jwk import JWKOKP
        data = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPIAha9VqyHHpY1GtEW8JXWqLU5mrPRhXPwJqCtL3bWZ
-----END PRIVATE KEY-----"""
        key = JWKOKP.load(data)
        data = key.to_partial_json()
        x = josepy.json_util.encode_b64jose(data['x'])
        self.assertEqual(x, "9ujoz88QZL05w2lhaqUbBaBpwmM12Y7Y8Ybfwjibk-I")

    def test_from_json(self):
        from josepy.jwk import JWK
        key = JWK.from_json(self.jwked25519json)
        with self.subTest(key=[
            self.jwked448json,
            self.jwked25519json,
            self.jwkx25519json,
            self.jwkx448json,
        ]):
            self.assertIsInstance(key.key, util.ComparableOKPKey)

    def test_fields_to_json(self):
        from josepy.jwk import JWK
        data = b"""-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPIAha9VqyHHpY1GtEW8JXWqLU5mrPRhXPwJqCtL3bWZ
-----END PRIVATE KEY-----"""
        key = JWK.load(data)
        data = key.fields_to_partial_json()
        self.assertEqual(data['crv'], "Ed25519")
        self.assertIsInstance(data['x'], bytes)

    def test_init_auto_comparable(self):
        self.assertIsInstance(self.x448_key.key, util.ComparableOKPKey)

    def test_unknown_crv_name(self):
        from josepy.jwk import JWK
        self.assertRaises(
            errors.DeserializationError, JWK.from_json,
            {
                'kty': 'OKP',
                'crv': 'Ed1000',
                'x': 'jjQtV-fA7J_tK8dPzYq7jRPNjF8r5p6LW2R25S2Gw5U',
            }
        )

    def test_no_x_name(self):
        from josepy.jwk import JWK
        with self.assertRaises(errors.DeserializationError) as warn:
            JWK.from_json(
                {
                    'kty': 'OKP',
                    'crv': 'Ed448',
                }
            )
        self.assertEqual(
            warn.exception.__str__(),
            'Deserialization error: OKP should have "x" parameter'
        )

    def test_from_json_hashable(self):
        from josepy.jwk import JWK
        hash(JWK.from_json(self.jwked25519json))

    def test_deserialize_public_key(self):
        # should target jwk.py:474-484, but those lines are still marked as missing
        # in the coverage report
        from josepy.jwk import JWKOKP
        JWKOKP.fields_from_json(self.jwked25519json)


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
