"""JOSE utilities."""
from __future__ import annotations
from collections.abc import Hashable, Iterator, Mapping, Callable
from typing import Any, TypeVar

from cryptography.hazmat.primitives.asymmetric import ec, rsa


class ComparableKey:
    """Comparable wrapper for ``cryptography`` keys.

    See https://github.com/pyca/cryptography/issues/2122.

    """

    __hash__: Callable[[], int] = NotImplemented

    def __init__(
        self,
        wrapped:
            rsa.RSAPrivateKeyWithSerialization |
            rsa.RSAPublicKeyWithSerialization |
            ec.EllipticCurvePrivateKeyWithSerialization |
            ec.EllipticCurvePublicKeyWithSerialization,
    ):
        self._wrapped = wrapped

    def __getattr__(self, name: str) -> Any:
        return getattr(self._wrapped, name)

    def __eq__(self, other: Any) -> bool:
        if (
            not isinstance(other, self.__class__)
            or self._wrapped.__class__ is not other._wrapped.__class__
        ):
            return NotImplemented
        elif hasattr(self._wrapped, "private_numbers"):
            return self.private_numbers() == other.private_numbers()
        elif hasattr(self._wrapped, "public_numbers"):
            return self.public_numbers() == other.public_numbers()
        else:
            return NotImplemented

    def __repr__(self) -> str:
        return "<{0}({1!r})>".format(self.__class__.__name__, self._wrapped)

    def public_key(self) -> "ComparableKey":
        """Get wrapped public key."""
        if isinstance(
            self._wrapped,
            (rsa.RSAPublicKeyWithSerialization, ec.EllipticCurvePublicKeyWithSerialization),
        ):
            return self

        return self.__class__(self._wrapped.public_key())


class ComparableRSAKey(ComparableKey):
    """Wrapper for ``cryptography`` RSA keys.

    Wraps around:

    - :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey`
    - :class:`~cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey`

    """

    def __hash__(self) -> int:
        # public_numbers() hasn't got stable hash!
        # https://github.com/pyca/cryptography/issues/2143
        if isinstance(self._wrapped, rsa.RSAPrivateKeyWithSerialization):
            priv = self.private_numbers()
            pub = priv.public_numbers
            return hash(
                (self.__class__, priv.p, priv.q, priv.dmp1, priv.dmq1, priv.iqmp, pub.n, pub.e)
            )
        elif isinstance(self._wrapped, rsa.RSAPublicKeyWithSerialization):
            pub = self.public_numbers()
            return hash((self.__class__, pub.n, pub.e))

        raise NotImplementedError()


class ComparableECKey(ComparableKey):
    """Wrapper for ``cryptography`` EC keys.
    Wraps around:
    - :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
    - :class:`~cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey`
    """

    def __hash__(self) -> int:
        # public_numbers() hasn't got stable hash!
        # https://github.com/pyca/cryptography/issues/2143
        if isinstance(self._wrapped, ec.EllipticCurvePrivateKeyWithSerialization):
            priv = self.private_numbers()
            pub = priv.public_numbers
            return hash((self.__class__, pub.curve.name, pub.x, pub.y, priv.private_value))
        elif isinstance(self._wrapped, ec.EllipticCurvePublicKeyWithSerialization):
            pub = self.public_numbers()
            return hash((self.__class__, pub.curve.name, pub.x, pub.y))

        raise NotImplementedError()


GenericImmutableMap = TypeVar("GenericImmutableMap", bound="ImmutableMap")


class ImmutableMap(Mapping, Hashable):
    """Immutable key to value mapping with attribute access."""

    __slots__: tuple[str, ...] = ()
    """Must be overridden in subclasses."""

    def __init__(self, **kwargs: Any) -> None:
        if set(kwargs) != set(self.__slots__):
            raise TypeError(
                "__init__() takes exactly the following arguments: {0} "
                "({1} given)".format(
                    ", ".join(self.__slots__), ", ".join(kwargs) if kwargs else "none"
                )
            )
        for slot in self.__slots__:
            object.__setattr__(self, slot, kwargs.pop(slot))

    def update(self: GenericImmutableMap, **kwargs: Any) -> GenericImmutableMap:
        """Return updated map."""
        items: Mapping[str, Any] = {**self, **kwargs}
        return type(self)(**items)

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return iter(self.__slots__)

    def __len__(self) -> int:
        return len(self.__slots__)

    def __hash__(self) -> int:
        return hash(tuple(getattr(self, slot) for slot in self.__slots__))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("can't set attribute")

    def __repr__(self) -> str:
        return "{0}({1})".format(
            self.__class__.__name__,
            ", ".join("{0}={1!r}".format(key, value) for key, value in self.items()),
        )


class frozendict(Mapping, Hashable):
    """Frozen dictionary."""

    __slots__ = ("_items", "_keys")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        items: Mapping
        if kwargs and not args:
            items = dict(kwargs)
        elif len(args) == 1 and isinstance(args[0], Mapping):
            items = args[0]
        else:
            raise TypeError()
        # TODO: support generators/iterators

        object.__setattr__(self, "_items", items)
        object.__setattr__(self, "_keys", tuple(sorted(items.keys())))

    def __getitem__(self, key: str) -> Any:
        return self._items[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._keys)

    def __len__(self) -> int:
        return len(self._items)

    def _sorted_items(self) -> tuple[tuple[str, Any], ...]:
        return tuple((key, self[key]) for key in self._keys)

    def __hash__(self) -> int:
        return hash(self._sorted_items())

    def __getattr__(self, name: str) -> Any:
        try:
            return self._items[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("can't set attribute")

    def __repr__(self) -> str:
        return "frozendict({0})".format(
            ", ".join("{0}={1!r}".format(key, value) for key, value in self._sorted_items())
        )
