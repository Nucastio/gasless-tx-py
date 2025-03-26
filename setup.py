from setuptools import setup, find_packages

setup(
    name='cardano-gasless-tx',
    version='1.0.2',
    packages=find_packages(),
    install_requires=[
        "setuptools",
        "wheel",
        "twine",
        "requests"
    ],
    # Other metadata...
)
