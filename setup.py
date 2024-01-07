import os

from setuptools import setup, find_packages

assert 'VIRTUAL_ENV' in os.environ, "Cannot install outside of a Python virtualenv"

setup(
    name='crush',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        # 'greed @ git+ssh://git@github.com:ucsb-seclab/greed.git@v1.0.0#egg=greed',
        'backoff',
        'ipython',
        'networkx',
        'web3'
    ],
    python_requires='>=3.8',
)

