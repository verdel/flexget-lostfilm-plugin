#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Parse the version from the mapbox module.
with open('plex2myshows/__init__.py') as f:
    for line in f:
        if line.find("__version__") >= 0:
            version = line.split("=")[1].strip()
            version = version.strip('"')
            version = version.strip("'")
            continue

with open(path.join(here, 'README.rst'), encoding='utf-8') as readme_file:
    readme = readme_file.read()

with open(path.join(here, 'HISTORY.rst'), encoding='utf-8') as history_file:
    history = history_file.read().replace('.. :changelog:', '')

requirements = [
    'FlexGet>2.2'
]

setup(
    name='Lostfilm-Flexget',
    version=version,
    description='Lostfilm FlexGet plugin',
    long_description=readme + '\n\n' + history,
    author='Vadim Aleksandrov',
    author_email='valeksandrov@me.com',
    url='https://github.com/verdel/flexget-lostfilm-plugin',
    packages=find_packages(),
    install_requires=requirements,
    keywords='lostfilm, lostfilm.tv, flexget, plugin',
    license='MIT',
    entry_points="""
        [FlexGet.plugins]
        lostfilm = extras.input.lostfilm""",

)
