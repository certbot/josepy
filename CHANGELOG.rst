Changelog
=========

1.10.0 (2021-09-27)
-------------------

* josepy is now compliant with PEP-561: type checkers will fetch types from the inline
  types annotations when josepy is installed as a dependency in a Python project.
* Added a `field` function to assist in adding type annotations for Fields in classes.
  If the field function is used to define a `Field` in a `JSONObjectWithFields` based
  class without a type annotation, an error will be raised.
* josepy's tests can no longer be imported under the name josepy, however, they are still
  included in the package and you can run them by installing josepy with "tests" extras and
  running `python -m pytest`.

1.9.0 (2021-09-09)
------------------

* Removed pytest-cache testing dependency.
* Fixed a bug that sometimes caused incorrect padding to be used when
  serializing Elliptic Curve keys as JSON Web Keys.

1.8.0 (2021-03-15)
------------------

* Removed external mock dependency.
* Removed dependency on six.
* Deprecated the module josepy.magic_typing.
* Fix JWS/JWK generation with EC keys when keys or signatures have leading zeros.

1.7.0 (2021-02-11)
------------------

* Dropped support for Python 2.7.
* Added support for EC keys.

1.6.0 (2021-01-26)
------------------

* Deprecated support for Python 2.7.

1.5.0 (2020-11-03)
------------------

* Added support for Python 3.9.
* Dropped support for Python 3.5.
* Stopped supporting running tests with ``python setup.py test`` which is
  deprecated in favor of ``python -m pytest``.

1.4.0 (2020-08-17)
------------------

* Deprecated support for Python 3.5.

1.3.0 (2020-01-28)
------------------

* Deprecated support for Python 3.4.
* Officially add support for Python 3.8.

1.2.0 (2019-06-28)
------------------

* Support for Python 2.6 and 3.3 has been removed.
* Known incompatibilities with Python 3.8 have been resolved.

1.1.0 (2018-04-13)
------------------

* Deprecated support for Python 2.6 and 3.3.
* Use the ``sign`` and ``verify`` methods when they are available in
  ``cryptography`` instead of the deprecated methods ``signer`` and
  ``verifier``.

1.0.1 (2017-10-25)
------------------

Stop installing mock as part of the default but only as part of the
testing dependencies.

1.0.0 (2017-10-13)
-------------------

First release after moving the josepy package into a standalone library.
