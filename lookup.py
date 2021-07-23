from urllib.request import Request, urlopen
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

def getIpHubData(addr: str):
    try:
        url = f'http://v2.api.iphub.info/ip/{addr}'
        r = Request(url)
        r.add_header('X-Key', os.environ.get("IPHUB_KEY"))
        try:
            response = json.loads(urlopen(r).read().decode('utf-8'))
        except:
            return None
        return response
    except Exception as e:
        print(f'{bcolors.FAIL}Error[IPHub]: {e} {bcolors.ENDC}')
        return None

    except Exception as e:
        print(f'{bcolors.FAIL}Error[IPHub]: {e} {bcolors.ENDC}')
        return None

def lookupfromCymru(addr: str):
    try:
        c = CymruClient() # init everytime on request due to bug in cymruclient.
        return c.lookup(addr)
    except Exception as e:
        print(f'{bcolors.FAIL}Error[Cymru]: {e} {bcolors.ENDC}')
        return None

def getIPHubReputationColorized(rep: int):
    if rep == 0:
        return f'{bcolors.OKGREEN}OK{bcolors.ENDC}'
    elif rep == 1:
        return f'{bcolors.FAIL}BAD{bcolors.ENDC}'
    elif rep == 2:
        return f'{bcolors.WARNING}WARNING{bcolors.ENDC}'
    else:
        return f'{bcolors.OKBLUE}UNKNOWN{bcolors.ENDC}'

def main(): 
    while True:
        addr = input("Request: ").strip()
        iphub = getIpHubData(addr)
        cymru = lookupfromCymru(addr)
        if iphub is not None and cymru is not None:
            print()
            print(f'IP: {addr}')
            print(f'Reputation: {getIPHubReputationColorized(iphub["block"])} (IPHub)')
            print(f'CIDR: {cymru.prefix}')
            asn = 'NA' if cymru.asn == 'NA' else f'AS{cymru.asn}'
            print(f'Info: {asn} {cymru.owner}')
            print()
        else:
            print(f'{bcolors.FAIL}Error[main]: Failed to get data {bcolors.ENDC}')
            print()


if __name__ == '__main__':
    main()

