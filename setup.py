import io

from setuptools import find_packages, setup

version = '1.5.0'

# Please update tox.ini when modifying dependency version requirements
install_requires = [
    # load_pem_private/public_key (>=0.6)
    # rsa_recover_prime_factors (>=0.8)
    'cryptography>=0.8',
    # Connection.set_tlsext_host_name (>=0.13)
    'PyOpenSSL>=0.13',
    # For pkg_resources. >=1.0 so pip resolves it to a version cryptography
    # will tolerate; see #2599:
    'setuptools>=1.0',
    'six>=1.9.0',  # needed for python_2_unicode_compatible
]

testing_requires = [
    'coverage>=4.0',
    'pytest-cache>=1.0',
    'pytest-cov',
    'flake8',
    'pytest-flake8>=0.5',
    'pytest>=2.8.0',
    'mock',
]

dev_extras = [
    'pytest',
    'tox',
]

dev3_extras = [
    'mypy',
]

docs_extras = [
    'Sphinx>=1.0',  # autodoc_member_order = 'bysource', autodoc_default_flags
    'sphinx_rtd_theme',
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
    python_requires='>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
    ],

    packages=find_packages(where='src'),
    package_dir={'': 'src'},
    include_package_data=True,
    install_requires=install_requires,
    extras_require={
        'dev': dev_extras,
        'dev3': dev3_extras,
        'docs': docs_extras,
        'tests': testing_requires,
    },
    entry_points={
        'console_scripts': [
            'jws = josepy.jws:CLI.run',
        ],
    },
)
