"""Tests for josepy.json_util."""
import itertools
import sys
import unittest
from typing import Any, Dict, Mapping
from unittest import mock

import pytest
import test_util

from josepy import errors, interfaces, util

CERT = test_util.load_comparable_cert('cert.pem')
CSR = test_util.load_comparable_csr('csr.pem')


class FieldTest(unittest.TestCase):
    """Tests for josepy.json_util.field and josepy.json_util.Field."""

    def test_field_function(self) -> None:
        from josepy.json_util import Field, field

        test = field("foo", default="bar")
        assert isinstance(test, Field)
        assert test.json_name == "foo"
        assert test.default == "bar"

    def test_type_field_control(self) -> None:
        from josepy.json_util import JSONObjectWithFields, field

        class DummyProperlyTyped(JSONObjectWithFields):
            type: str = field('type')
            index: int = field('index')

        with pytest.raises(ValueError):
            class DummyImproperlyTyped(JSONObjectWithFields):
                type = field('type')
                index: int = field('index')

    def test_no_omit_boolean(self) -> None:
        from josepy.json_util import Field
        for default, omitempty, value in itertools.product(
                [True, False], [True, False], [True, False]):
            assert Field("foo", default=default, omitempty=omitempty).omit(value) is False

    def test_descriptors(self) -> None:
        mock_value = mock.MagicMock()

        def decoder(unused_value: Any) -> str:
            return 'd'

        def encoder(unused_value: Any) -> str:
            return 'e'

        from josepy.json_util import Field
        field = Field('foo')

        field = field.encoder(encoder)
        assert 'e' == field.encode(mock_value)

        field = field.decoder(decoder)
        assert 'e' == field.encode(mock_value)
        assert 'd' == field.decode(mock_value)

    def test_default_encoder_is_partial(self) -> None:
        class MockField(interfaces.JSONDeSerializable):
            def to_partial_json(self) -> Dict[str, Any]:
                return {'foo': 'bar'}  # pragma: no cover

            @classmethod
            def from_json(cls, jobj: Mapping[str, Any]) -> 'MockField':
                return cls()  # pragma: no cover
        mock_field = MockField()

        from josepy.json_util import Field
        assert Field.default_encoder(mock_field) is mock_field
        # in particular...
        assert 'foo' != Field.default_encoder(mock_field)

    def test_default_encoder_passthrough(self) -> None:
        mock_value = mock.MagicMock()
        from josepy.json_util import Field
        assert Field.default_encoder(mock_value) is mock_value

    def test_default_decoder_list_to_tuple(self) -> None:
        from josepy.json_util import Field
        assert (1, 2, 3) == Field.default_decoder([1, 2, 3])

    def test_default_decoder_dict_to_frozendict(self) -> None:
        from josepy.json_util import Field
        obj = Field.default_decoder({'x': 2})
        assert isinstance(obj, util.frozendict)
        assert obj == util.frozendict(x=2)

    def test_default_decoder_passthrough(self) -> None:
        mock_value = mock.MagicMock()
        from josepy.json_util import Field
        assert Field.default_decoder(mock_value) is mock_value


class JSONObjectWithFieldsMetaTest(unittest.TestCase):
    """Tests for josepy.json_util.JSONObjectWithFieldsMeta."""

    def setUp(self) -> None:
        from josepy.json_util import Field, JSONObjectWithFieldsMeta
        self.field = Field('Baz')
        self.field2 = Field('Baz2')

        class A(metaclass=JSONObjectWithFieldsMeta):
            __slots__ = ('bar',)
            baz = self.field

        class B(A):
            pass

        class C(A):
            baz = self.field2

        self.a_cls = A
        self.b_cls = B
        self.c_cls = C

    def test_fields(self) -> None:
        assert {'baz': self.field} == self.a_cls._fields
        assert {'baz': self.field} == self.b_cls._fields

    def test_fields_inheritance(self) -> None:
        assert {'baz': self.field2} == self.c_cls._fields

    def test_slots(self) -> None:
        assert ('bar', 'baz') == self.a_cls.__slots__
        assert ('baz',) == self.b_cls.__slots__

    def test_orig_slots(self) -> None:
        assert ('bar',) == self.a_cls._orig_slots
        assert () == self.b_cls._orig_slots


class JSONObjectWithFieldsTest(unittest.TestCase):
    """Tests for josepy.json_util.JSONObjectWithFields."""

    def setUp(self) -> None:
        from josepy.json_util import Field, JSONObjectWithFields

        class MockJSONObjectWithFields(JSONObjectWithFields):
            x = Field('x', omitempty=True,
                      encoder=(lambda x: x * 2),
                      decoder=(lambda x: x / 2))
            y = Field('y')
            z = Field('Z')  # on purpose uppercase

            @y.encoder  # type: ignore
            def y(value):
                if value == 500:
                    raise errors.SerializationError()
                return value

            @y.decoder  # type: ignore
            def y(value):
                if value == 500:
                    raise errors.DeserializationError()
                return value

        self.MockJSONObjectWithFields = MockJSONObjectWithFields
        self.mock = MockJSONObjectWithFields(x=None, y=2, z=3)

    def test_init_defaults(self) -> None:
        assert self.mock == self.MockJSONObjectWithFields(y=2, z=3)

    def test_encode(self) -> None:
        assert 10 == self.MockJSONObjectWithFields(
            x=5, y=0, z=0).encode("x")

    def test_encode_wrong_field(self) -> None:
        with pytest.raises(errors.Error):
            self.mock.encode('foo')

    def test_encode_serialization_error_passthrough(self) -> None:
        with pytest.raises(errors.SerializationError):
            self.MockJSONObjectWithFields(y=500, z=None).encode("y")

    def test_fields_to_partial_json_omits_empty(self) -> None:
        assert self.mock.fields_to_partial_json() == {'y': 2, 'Z': 3}

    def test_fields_from_json_fills_default_for_empty(self) -> None:
        assert {'x': None, 'y': 2, 'z': 3} == \
            self.MockJSONObjectWithFields.fields_from_json({'y': 2, 'Z': 3})

    def test_fields_from_json_fails_on_missing(self) -> None:
        with pytest.raises(errors.DeserializationError):
            self.MockJSONObjectWithFields.fields_from_json({'y': 0})
        with pytest.raises(errors.DeserializationError):
            self.MockJSONObjectWithFields.fields_from_json({'Z': 0})
        with pytest.raises(errors.DeserializationError):
            self.MockJSONObjectWithFields.fields_from_json({'x': 0, 'y': 0})
        with pytest.raises(errors.DeserializationError):
            self.MockJSONObjectWithFields.fields_from_json({'x': 0, 'Z': 0})

    def test_fields_to_partial_json_encoder(self) -> None:
        assert self.MockJSONObjectWithFields(x=1, y=2, z=3).to_partial_json() == \
            {'x': 2, 'y': 2, 'Z': 3}

    def test_fields_from_json_decoder(self) -> None:
        assert {'x': 2, 'y': 2, 'z': 3} == \
            self.MockJSONObjectWithFields.fields_from_json(
                {'x': 4, 'y': 2, 'Z': 3})

    def test_fields_to_partial_json_error_passthrough(self) -> None:
        with pytest.raises(errors.SerializationError):
            self.MockJSONObjectWithFields(
                x=1, y=500, z=3).to_partial_json()

    def test_fields_from_json_error_passthrough(self) -> None:
        with pytest.raises(errors.DeserializationError):
            self.MockJSONObjectWithFields.from_json({'x': 4, 'y': 500, 'Z': 3})


class DeEncodersTest(unittest.TestCase):
    def setUp(self) -> None:
        self.b64_cert = (
            u'MIIB3jCCAYigAwIBAgICBTkwDQYJKoZIhvcNAQELBQAwdzELMAkGA1UEBhM'
            u'CVVMxETAPBgNVBAgMCE1pY2hpZ2FuMRIwEAYDVQQHDAlBbm4gQXJib3IxKz'
            u'ApBgNVBAoMIlVuaXZlcnNpdHkgb2YgTWljaGlnYW4gYW5kIHRoZSBFRkYxF'
            u'DASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTE0MTIxMTIyMzQ0NVoXDTE0MTIx'
            u'ODIyMzQ0NVowdzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1pY2hpZ2FuMRI'
            u'wEAYDVQQHDAlBbm4gQXJib3IxKzApBgNVBAoMIlVuaXZlcnNpdHkgb2YgTW'
            u'ljaGlnYW4gYW5kIHRoZSBFRkYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFwwD'
            u'QYJKoZIhvcNAQEBBQADSwAwSAJBAKx1c7RR7R_drnBSQ_zfx1vQLHUbFLh1'
            u'AQQQ5R8DZUXd36efNK79vukFhN9HFoHZiUvOjm0c-pVE6K-EdE_twuUCAwE'
            u'AATANBgkqhkiG9w0BAQsFAANBAC24z0IdwIVKSlntksllvr6zJepBH5fMnd'
            u'fk3XJp10jT6VE-14KNtjh02a56GoraAvJAT5_H67E8GvJ_ocNnB_o'
        )
        self.b64_csr = (
            u'MIIBXTCCAQcCAQAweTELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE1pY2hpZ2F'
            u'uMRIwEAYDVQQHDAlBbm4gQXJib3IxDDAKBgNVBAoMA0VGRjEfMB0GA1UECw'
            u'wWVW5pdmVyc2l0eSBvZiBNaWNoaWdhbjEUMBIGA1UEAwwLZXhhbXBsZS5jb'
            u'20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEArHVztFHtH92ucFJD_N_HW9As'
            u'dRsUuHUBBBDlHwNlRd3fp580rv2-6QWE30cWgdmJS86ObRz6lUTor4R0T-3'
            u'C5QIDAQABoCkwJwYJKoZIhvcNAQkOMRowGDAWBgNVHREEDzANggtleGFtcG'
            u'xlLmNvbTANBgkqhkiG9w0BAQsFAANBAHJH_O6BtC9aGzEVCMGOZ7z9iIRHW'
            u'Szr9x_bOzn7hLwsbXPAgO1QxEwL-X-4g20Gn9XBE1N9W6HCIEut2d8wACg'
        )

    def test_encode_b64jose(self) -> None:
        from josepy.json_util import encode_b64jose
        encoded = encode_b64jose(b'x')
        assert isinstance(encoded, str)
        assert u'eA' == encoded

    def test_decode_b64jose(self) -> None:
        from josepy.json_util import decode_b64jose
        decoded = decode_b64jose(u'eA')
        assert isinstance(decoded, bytes)
        assert b'x' == decoded

    def test_decode_b64jose_padding_error(self) -> None:
        from josepy.json_util import decode_b64jose
        with pytest.raises(errors.DeserializationError):
            decode_b64jose(u'x')

    def test_decode_b64jose_size(self) -> None:
        from josepy.json_util import decode_b64jose
        assert b'foo' == decode_b64jose(u'Zm9v', size=3)
        with pytest.raises(errors.DeserializationError):
            decode_b64jose(u'Zm9v', size=2)
        with pytest.raises(errors.DeserializationError):
            decode_b64jose(u'Zm9v', size=4)

    def test_decode_b64jose_minimum_size(self) -> None:
        from josepy.json_util import decode_b64jose
        assert b'foo' == decode_b64jose(u'Zm9v', size=3, minimum=True)
        assert b'foo' == decode_b64jose(u'Zm9v', size=2, minimum=True)
        with pytest.raises(errors.DeserializationError):
            decode_b64jose(u'Zm9v', size=4, minimum=True)

    def test_encode_hex16(self) -> None:
        from josepy.json_util import encode_hex16
        encoded = encode_hex16(b'foo')
        assert u'666f6f' == encoded
        assert isinstance(encoded, str)

    def test_decode_hex16(self) -> None:
        from josepy.json_util import decode_hex16
        decoded = decode_hex16(u'666f6f')
        assert b'foo' == decoded
        assert isinstance(decoded, bytes)

    def test_decode_hex16_minimum_size(self) -> None:
        from josepy.json_util import decode_hex16
        assert b'foo' == decode_hex16(u'666f6f', size=3, minimum=True)
        assert b'foo' == decode_hex16(u'666f6f', size=2, minimum=True)
        with pytest.raises(errors.DeserializationError):
            decode_hex16(u'666f6f', size=4, minimum=True)

    def test_decode_hex16_odd_length(self) -> None:
        from josepy.json_util import decode_hex16
        with pytest.raises(errors.DeserializationError):
            decode_hex16(u'x')

    def test_encode_cert(self) -> None:
        from josepy.json_util import encode_cert
        assert self.b64_cert == encode_cert(CERT)

    def test_decode_cert(self) -> None:
        from josepy.json_util import decode_cert
        cert = decode_cert(self.b64_cert)
        assert isinstance(cert, util.ComparableX509)
        assert cert == CERT
        with pytest.raises(errors.DeserializationError):
            decode_cert(u'')

    def test_encode_csr(self) -> None:
        from josepy.json_util import encode_csr
        assert self.b64_csr == encode_csr(CSR)

    def test_decode_csr(self) -> None:
        from josepy.json_util import decode_csr
        csr = decode_csr(self.b64_csr)
        assert isinstance(csr, util.ComparableX509)
        assert csr == CSR
        with pytest.raises(errors.DeserializationError):
            decode_csr(u'')


class TypedJSONObjectWithFieldsTest(unittest.TestCase):

    def setUp(self) -> None:
        from josepy.json_util import TypedJSONObjectWithFields

        class MockParentTypedJSONObjectWithFields(TypedJSONObjectWithFields):
            TYPES = {}
            type_field_name = 'type'

        @MockParentTypedJSONObjectWithFields.register
        class MockTypedJSONObjectWithFields(
                MockParentTypedJSONObjectWithFields):
            foo: str
            typ = 'test'
            __slots__ = ('foo',)

            @classmethod
            def fields_from_json(cls, jobj: Mapping[str, Any]) -> Dict[str, Any]:
                return {'foo': jobj['foo']}

            def fields_to_partial_json(self) -> Any:
                return {'foo': self.foo}

        self.parent_cls = MockParentTypedJSONObjectWithFields
        self.msg = MockTypedJSONObjectWithFields(foo='bar')

    def test_to_partial_json(self) -> None:
        assert self.msg.to_partial_json() == {
            'type': 'test',
            'foo': 'bar',
        }

    def test_from_json_non_dict_fails(self) -> None:
        for value in [[], (), 5, "asd"]:  # all possible input types
            with pytest.raises(errors.DeserializationError):
                # We're purposefully testing with the incorrect type here.
                self.parent_cls.from_json(value)  # type: ignore

    def test_from_json_dict_no_type_fails(self) -> None:
        with pytest.raises(errors.DeserializationError):
            self.parent_cls.from_json({})

    def test_from_json_unknown_type_fails(self) -> None:
        with pytest.raises(errors.UnrecognizedTypeError):
            self.parent_cls.from_json({'type': 'bar'})

    def test_from_json_returns_obj(self) -> None:
        assert {'foo': 'bar'} == self.parent_cls.from_json(
            {'type': 'test', 'foo': 'bar'})


if __name__ == '__main__':
    sys.exit(pytest.main(sys.argv[1:] + [__file__]))  # pragma: no cover
