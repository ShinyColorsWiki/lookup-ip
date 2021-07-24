"""
LookUp IP

The MIT License (MIT)

Copyright (c) 2021 shinycolors.wiki
"""

__version__ = '0.3.0'
__author__ = 'MPThLee'
__maintainer__ = 'MPThLee'
__copyright__ = 'Copyright (c) 2021 shinycolors.wiki'
__license__ = 'MIT'


from urllib.request import Request, urlopen
import asyncio
import argparse
import json
import os

from cymruwhois import Client as CymruClient
from dotenv import load_dotenv

load_dotenv()


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


async def getIpHubData(addr: str):
    try:
        url = f'http://v2.api.iphub.info/ip/{addr}'
        r = Request(url)
        r.add_header('X-Key', os.environ.get("IPHUB_KEY"))
        try:
            response = json.loads(urlopen(r).read().decode('utf-8'))
        except Exception as e:
            print(f'{bcolors.FAIL}Error[IPHub]: {e} {bcolors.ENDC}')
            return None
        return response["block"]
    except Exception as e:
        print(f'{bcolors.FAIL}Error[IPHub]: {e} {bcolors.ENDC}')
        return None


async def getVPNAPIData(addr: str):
    try:
        url = f'https://vpnapi.io/api/{addr}?key={os.environ.get("VPNAPI_KEY")}'
        r = Request(url)
        try:
            response = json.loads(urlopen(r).read().decode('utf-8'))
        except Exception as e:
            print(f'{bcolors.FAIL}Error[VPNAPI]: {e} {bcolors.ENDC}')
            return None
        return response["security"]["vpn"] or response["security"]["proxy"] or response["security"]["tor"]
    except Exception as e:
        print(f'{bcolors.FAIL}Error[VPNAPI]: {e} {bcolors.ENDC}')
        return None


async def getProxyCheckData(addr: str):
    try:
        key = f'?key={os.environ.get("PROXYCHECK_KEY")}' if os.environ.get(
            "PROXYCHECK_KEY") is not None else ''
        url = f'https://proxycheck.io/v2/{addr}{key}'
        r = Request(url)
        try:
            response = json.loads(urlopen(r).read().decode('utf-8'))
        except Exception as e:
            print(f'{bcolors.FAIL}Error[ProxyCheck]: {e} {bcolors.ENDC}')
            return None
        if response["status"] == "ok":
            return response[addr]["type"] in ["Hosting", "TOR", "SOCKS", "SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS5H", "Shadowsocks", "OpenVPN", "VPN"]
        else:
            return None
    except Exception as e:
        print(f'{bcolors.FAIL}Error[ProxyCheck]: {e} {bcolors.ENDC}')
        return None


async def lookupfromCymru(addr: str):
    try:
        # init everytime on request due to bug in cymruclient.
        c = CymruClient()
        return c.lookup(addr)
    except Exception as e:
        print(f'{bcolors.FAIL}Error[Cymru]: {e} {bcolors.ENDC}')
        return None


def getIPHubReputationColorized(rep):
    if rep is None:
        return f'{bcolors.OKBLUE}UNKNOWN{bcolors.ENDC}'
    elif rep == 0:
        return f'{bcolors.OKGREEN}OK{bcolors.ENDC}'
    elif rep == 1:
        return f'{bcolors.FAIL}BAD{bcolors.ENDC}'
    elif rep == 2:
        return f'{bcolors.WARNING}WARNING{bcolors.ENDC}'
    else:
        return f'{bcolors.OKBLUE}UNKNOWN{bcolors.ENDC}'


def getBoolColorized(isproxy):
    if isproxy:
        return f'{bcolors.FAIL}BAD{bcolors.ENDC}'
    elif isproxy is None:
        return f'{bcolors.OKBLUE}UNKNOWN{bcolors.ENDC}'
    else:
        return f'{bcolors.OKGREEN}OK{bcolors.ENDC}'


async def result(addr: str):
    futures = [
        asyncio.create_task(i) for i in [
            lookupfromCymru(addr), getIpHubData(addr),
            getVPNAPIData(addr), getProxyCheckData(addr)
        ]
    ]
    result = await asyncio.gather(*futures)

    cymru = result[0]
    iphub = getIPHubReputationColorized(result[1])
    vpnapi = getBoolColorized(result[2])
    proxycheck = getBoolColorized(result[3])

    if result[0] is not None:  # Cymru is must not be None.
        print(f'IP: {addr}')
        print(
            f'Reputation: {iphub} (IPHub), {vpnapi} (VPNAPI), {proxycheck} (ProxyCheck)')
        print(f'CIDR: {cymru.prefix}')
        asn = 'NA' if cymru.asn == 'NA' else f'AS{cymru.asn}'
        print(f'Info: {asn} {cymru.owner}')
        print()
    else:
        print(f'{bcolors.FAIL}Error[main]: Failed to get data. {bcolors.ENDC}')
        print(f'Result was: {result}')
        print()


async def loop_main():
    while True:
        addr = input("Request: ").strip()
        if addr == "":
            continue
        print()
        await result(addr)


async def main():
    parser = argparse.ArgumentParser(
        description='Lookup IP Addresses with reputation.')
    parser.add_argument('-a', '--addr', action='append',
                        help='IP Address to lookup.')
    parser.add_argument('-v', '--version', action='version',
                        version='%(prog)s ' + __version__)
    args = parser.parse_args()

    if args.addr is None:
        await loop_main()
    else:
        for addr in args.addr:
            await result(addr)


if __name__ == '__main__':
    asyncio.run(main())
