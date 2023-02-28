"""Tests for josepy.interfaces."""
from typing import Any, Dict, List
import unittest


class JSONDeSerializableTest(unittest.TestCase):

    def setUp(self) -> None:
        from josepy.interfaces import JSONDeSerializable

        class Basic(JSONDeSerializable):
            def __init__(self, v: Any) -> None:
                self.v = v

            def to_partial_json(self) -> Any:
                return self.v

            @classmethod
            def from_json(cls, jobj: Any) -> Basic:
                return cls(jobj)

        class Sequence(JSONDeSerializable):
            def __init__(self, x: Basic, y: Basic) -> None:
                self.x = x
                self.y = y

            def to_partial_json(self) -> List[Basic]:
                return [self.x, self.y]

            @classmethod
            def from_json(cls, jobj: List[Any]) -> Sequence:
                return cls(
                    Basic.from_json(jobj[0]), Basic.from_json(jobj[1]))

        class Mapping(JSONDeSerializable):
            def __init__(self, x: Any, y: Any) -> None:
                self.x = x
                self.y = y

            def to_partial_json(self) -> Dict[Basic, Basic]:
                return {self.x: self.y}

            @classmethod
            def from_json(cls, jobj: Any) -> Mapping:
                return cls('dummy', 'values')  # pragma: no cover

        self.basic1 = Basic('foo1')
        self.basic2 = Basic('foo2')
        self.seq = Sequence(self.basic1, self.basic2)
        self.mapping = Mapping(self.basic1, self.basic2)
        self.nested = Basic([[self.basic1]])
        self.tuple = Basic(('foo',))

        self.Basic = Basic
        self.Sequence = Sequence
        self.Mapping = Mapping

    def test_to_json_sequence(self) -> None:
        self.assertEqual(self.seq.to_json(), ['foo1', 'foo2'])

    def test_to_json_mapping(self) -> None:
        self.assertEqual(self.mapping.to_json(), {'foo1': 'foo2'})

    def test_to_json_other(self) -> None:
        mock_value = object()
        self.assertIs(self.Basic(mock_value).to_json(), mock_value)

    def test_to_json_nested(self) -> None:
        self.assertEqual(self.nested.to_json(), [['foo1']])

    def test_to_json(self) -> None:
        self.assertEqual(self.tuple.to_json(), (('foo', )))

    def test_from_json_not_implemented(self) -> None:
        from josepy.interfaces import JSONDeSerializable
        self.assertRaises(TypeError, JSONDeSerializable.from_json, 'xxx')

    def test_json_loads(self) -> None:
        seq = self.Sequence.json_loads('["foo1", "foo2"]')
        self.assertIsInstance(seq, self.Sequence)
        self.assertIsInstance(seq.x, self.Basic)
        self.assertIsInstance(seq.y, self.Basic)
        self.assertEqual(seq.x.v, 'foo1')
        self.assertEqual(seq.y.v, 'foo2')

    def test_json_dumps(self) -> None:
        self.assertEqual('["foo1", "foo2"]', self.seq.json_dumps())

    def test_json_dumps_pretty(self) -> None:
        self.assertEqual(self.seq.json_dumps_pretty(),
                         '[\n    "foo1",\n    "foo2"\n]')

    def test_json_dump_default(self) -> None:
        from josepy.interfaces import JSONDeSerializable

        self.assertEqual(
            'foo1', JSONDeSerializable.json_dump_default(self.basic1))

        jobj = JSONDeSerializable.json_dump_default(self.seq)
        self.assertEqual(len(jobj), 2)
        self.assertIs(jobj[0], self.basic1)
        self.assertIs(jobj[1], self.basic2)

    def test_json_dump_default_type_error(self) -> None:
        from josepy.interfaces import JSONDeSerializable
        self.assertRaises(
            TypeError, JSONDeSerializable.json_dump_default, object())


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
