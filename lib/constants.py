# -*- coding: utf-8 -*-
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2018 The Electrum developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import json


def read_json(filename, default):
    path = os.path.join(os.path.dirname(__file__), filename)
    try:
        with open(path, 'r') as f:
            r = json.loads(f.read())
    except:
        r = default
    return r


class NewYorkCoinMainnet:

    TESTNET = False
    WIF_PREFIX = 0xbc
    ADDRTYPE_P2PKH = 60
    ADDRTYPE_P2SH = 22
    SEGWIT_HRP = "nyc"
    GENESIS = "5597f25c062a3038c7fd815fe46c67dedfcb3c839fbc8e01ed4044540d08fe48"
    DEFAULT_PORTS = {'t': '50001', 's': '50002'}
    DEFAULT_SERVERS = read_json('servers.json', {})
    CHECKPOINTS = read_json('checkpoints.json', [])

    XPRV_HEADERS = {
        'standard':    0x0488ade4,  # xprv
        'p2wpkh-p2sh': 0x049d7878,  # yprv
        'p2wsh-p2sh':  0x0295b005,  # Yprv
        'p2wpkh':      0x04b2430c,  # zprv
        'p2wsh':       0x02aa7a99,  # Zprv
    }
    XPUB_HEADERS = {
        'standard':    0x0488b21e,  # xpub
        'p2wpkh-p2sh': 0x049d7cb2,  # ypub
        'p2wsh-p2sh':  0x0295b43f,  # Ypub
        'p2wpkh':      0x04b24746,  # zpub
        'p2wsh':       0x02aa7ed3,  # Zpub
    }

class NewYorkCoinTestnet:

    TESTNET = True
    WIF_PREFIX = 0xf1
    ADDRTYPE_P2PKH = 113
    ADDRTYPE_P2SH = 196
    SEGWIT_HRP = "tnyc"
    GENESIS = "24463e4d3c625b0a9059f309044c2cf0d7e196cf2a6ecce901f24f681be33c8f"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = read_json('servers_testnet.json', {})
    CHECKPOINTS = read_json('checkpoints_testnet.json', [])

    XPRV_HEADERS = {
        'standard': 0x0488ade4,
        'p2wpkh-p2sh': 0x049d7878,
        'p2wsh-p2sh': 0x295b005,
        'p2wpkh': 0x4b2430c,
        'p2wsh': 0x2aa7a99
    }
    XPUB_HEADERS = {
        'standard': 0x0488b21e,
        'p2wpkh-p2sh': 0x049d7cb2,
        'p2wsh-p2sh': 0x295b43f,
        'p2wpkh': 0x4b24746,
        'p2wsh': 0x2aa7ed3
    }




#class BitcoinRegtest(BitcoinTestnet):

#    SEGWIT_HRP = "rnyc"
#    GENESIS = "530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"
#    DEFAULT_SERVERS = read_json('servers_regtest.json', {})
#    CHECKPOINTS = []


# don't import net directly, import the module instead (so that net is singleton)
net = NewYorkCoinMainnet


def set_mainnet():
    global net
    net = NewYorkCoinMainnet


def set_testnet():
    global net
    net = NewYorkCoinTestnet


#def set_regtest():
#    global net
#    net = BitcoinRegtest
