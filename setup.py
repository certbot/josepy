import io

from setuptools import find_packages, setup

version = '1.13.0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    # load_pem_private/public_key (>=0.6)
    # rsa_recover_prime_factors (>=0.8)
    # add sign() and verify() to asymetric keys (RSA >=1.4, ECDSA >=1.5)
    'cryptography>=1.5',
    # Connection.set_tlsext_host_name (>=0.13)
    'PyOpenSSL>=0.13',
    # For pkg_resources. >=1.0 so pip resolves it to a version cryptography
    # will tolerate; see #2599:
    'setuptools>=1.0',
]

testing_requires = [
    'coverage>=4.0',
    # Issue with flake8 4.0.0 and 4.0.1, see https://github.com/tholo/pytest-flake8/issues/81
    'flake8<4',
    'isort',
    'mypy',
    'pytest-cov',
    'pytest-flake8>=0.5',
    'pytest>=2.8.0',
    'types-pyOpenSSL',
    'types-pyRFC3339',
    'types-requests',
    'types-setuptools',
]

dev_extras = [
    'pytest',
    'tox',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme>=1.0',
]


with io.open('README.rst', encoding='UTF-8') as f:
    long_description = f.read()


setup(
    name='josepy',
    version=version,
    description='JOSE protocol implementation in Python',
    long_description=long_description,
    url='https://github.com/certbot/josepy',
    author="Certbot Project",
    author_email='client-dev@letsencrypt.org',
    license='Apache License 2.0',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'docs': docs_extras,
        'tests': testing_requires,
    },
    entry_points={
        'console_scripts': [
            'jws = josepy.jws:CLI.run',
        ],
    },
)
