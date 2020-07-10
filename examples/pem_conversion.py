from __future__ import print_function  # Python2 support

import josepy
from cryptography.hazmat.primitives import serialization


def jwk_to_pem(pkey_jwk):
    """
    LetsEncrypt uses RSA Private Keys as Account Keys.
    Certbot stores the Account Keys as a JWK (JSON Web Key) encoded string.
    Many non-certbot clients store the Account Keys using PEM encoding.

    Developers may need to utilize a Private Key in the PEM encoding for certain
    operations or to migrate existing LetsEncrypt accounts to a client.

    :param pkey_jwk: JSON Web Key(jwk) encoded RSA Private Key
    :type pkey_jwk: string

    :return: PEM encoded RSA Private Key
    :rtype: string
    """
    pkey = josepy.JWKRSA.json_loads(pkey_jwk)
    as_pem = pkey.key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return as_pem


def pem_to_jwk(pkey_pem, format="string"):
    """
    LetsEncrypt uses RSA Private Keys as Account Keys.
    Certbot stores the Account Keys as a JWK (JSON Web Key) encoded string.
    Many non-certbot clients store the Account Keys using PEM encoding.

    Developers may need to utilize a Private Key in the JWK format for certain
    operations or to migrate existing LetsEncrypt accounts to a client.

    :param pkey_pem: PEM encoded RSA Private Key
    :type pkey_pem: string

    :param format: Should the format be the JWK as a dict or JSON?, default string
    :type format: string, optional

    :return: JSON Web Key(jwk) encoded RSA Private Key
    :rtype: string or dict
    """
    if format not in ("string", "dict"):
        raise ValueError("`format` must be one of: string, dict")
    pkey = josepy.JWKRSA.load(pkey_pem)
    if format == "dict":
        # ``.fields_to_partial_json()` does not encode the `kty` Key Identifier
        as_jwk = pkey.to_json()
    else:
        # format == "string"
        as_jwk = pkey.json_dumps()
    return as_jwk


if __name__ == "__main__":
    """
    Certbot stores account data on a disk using this pattern:

        /etc/letsencrypt/accounts/##ACME_SERVER##/directory/##ACCOUNT##

    Each ACCOUNT folder has three files

        /private_key.json - JWK encoded RSA Private Key
        /meta.json - metadata
        /regr.json - registration information

    This example is only concerned with the `/private_key.json` file
    """
    import sys
    import json

    _args = sys.argv
    if len(_args) == 2:
        json_data = open(_args[1]).read()
        as_pem = jwk_to_pem(json_data)
        print(as_pem)
    elif len(_args) == 3 and _args[2] == "roundtrip":
        json_data = open(_args[1]).read()
        as_pem = jwk_to_pem(json_data)
        as_jwk = pem_to_jwk(as_pem)
        assert json.loads(as_jwk) == json.loads(json_data)
        print(as_pem)
        print("> roundtrip >")
        print(as_jwk)
    else:
        print("Error.")
        print("Invoke this script with a single argument: the path to a certbot key.")
        print(
            "   python pem_conversion.py /etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/##ACCOUNT##/private_key.json"
        )
        print(
            "Optional: add the string 'roundtrip' after the key to perform a roundtrip"
        )
        print(
            "   python pem_conversion.py /etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory/##ACCOUNT##/private_key.json roundtrip"
        )
