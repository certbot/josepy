Changelog
=========

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
