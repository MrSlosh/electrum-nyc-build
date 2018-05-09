#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

from setuptools import setup
import os
import sys
import platform
import imp
import argparse

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

with open('contrib/requirements/requirements-hw.txt') as f:
    requirements_hw = f.read().splitlines()

version = imp.load_source('version', 'lib/version.py')

if sys.version_info[:3] < (3, 4, 0):
    sys.exit("Error: Electrum requires Python version >= 3.4.0...")

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    opts, _ = parser.parse_known_args(sys.argv[1:])
    usr_share = os.path.join(sys.prefix, "share")
    icons_dirname = 'pixmaps'
    if not os.access(opts.root_path + usr_share, os.W_OK) and \
       not os.access(opts.root_path, os.W_OK):
        icons_dirname = 'icons'
        if 'XDG_DATA_HOME' in os.environ.keys():
            usr_share = os.environ['XDG_DATA_HOME']
        else:
            usr_share = os.path.expanduser('~/.local/share')
    data_files += [
        (os.path.join(usr_share, 'applications/'), ['electrum-nyc.desktop']),
        (os.path.join(usr_share, icons_dirname), ['icons/electrum-nyc.png'])
    ]

setup(
    name="Electrum-NYC",
    version=version.ELECTRUM_VERSION,
    install_requires=requirements,
    extras_require={
        'full': requirements_hw + ['pycryptodomex', 'scrypt>=0.6.0'],
    },
    packages=[
        'electrum_nyc',
        'electrum_nyc_gui',
        'electrum_nyc_gui.qt',
        'electrum_nyc_plugins',
        'electrum_nyc_plugins.audio_modem',
        'electrum_nyc_plugins.cosigner_pool',
        'electrum_nyc_plugins.email_requests',
        'electrum_nyc_plugins.hw_wallet',
        'electrum_nyc_plugins.keepkey',
        'electrum_nyc_plugins.labels',
        'electrum_nyc_plugins.ledger',
        'electrum_nyc_plugins.trezor',
        'electrum_nyc_plugins.digitalbitbox',
        'electrum_nyc_plugins.virtualkeyboard',
    ],
    package_dir={
        'electrum_nyc': 'lib',
        'electrum_nyc_gui': 'gui',
        'electrum_nyc_plugins': 'plugins',
    },
    package_data={
        'electrum_nyc': [
            'servers.json',
            'servers_testnet.json',
            'servers_regtest.json',
            'currencies.json',
            'checkpoints.json',
            'checkpoints_testnet.json',
            'www/index.html',
            'wordlist/*.txt',
            'locale/*/LC_MESSAGES/electrum.mo',
        ]
    },
    scripts=['electrum-nyc'],
    data_files=data_files,
    description="Lightweight NewYorkCoin Wallet",
    author="Thomas Voegtlin",
    author_email="thomasv@electrum.org",
    license="MIT Licence",
    url="http://electrum-nyc.org",
    long_description="""Lightweight NewYorkCoin Wallet"""
)
