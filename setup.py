import setuptools


def long_description():
    with open('README.md', 'r') as file:
        return file.read()


setuptools.setup(
    name='http-signature-client',
    version='0.0.0',
    author='Michal Charemza',
    author_email='michal@charemza.name',
    description='Implementation of the client side of the IETF draft "Signing HTTP Messages"',
    long_description=long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/michalc/python-http-signature-client',
    py_modules=[
        'http_signature_client',
    ],
    python_requires='>=3.5.0',
    install_requires=[
        'cryptography>=2.9.2,<3',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security :: Cryptography',
    ],
)
