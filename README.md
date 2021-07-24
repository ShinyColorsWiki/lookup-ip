LookUp IP
=========
This used for blocking ip range which has bad ip like vpn, proxy, hosting.

Formatting for Info block: `[ASNumber] [AS Owner], [Country]`

# Usage
```sh
$ pipenv install
# Alternatively, $ pip install python-dotenv cymruwhois
$ pipenv run python lookup.py
# Alternatively, $ python lookup.py
Request: 1.1.1.1

IP: 1.1.1.1
Reputation: OK (IPHub), BAD (VPNAPI), OK (ProxyCheck)
CIDR: 1.1.1.0/24
Info: AS13335 CLOUDFLARENET, US

Request:
...
```

# Required APIKey
It need to be set in `.env` file.
 * [IPHub](https://iphub.info/): `IPHUB_APIKEY`
 * [VPNAPI](https://vpnapi.io/): `VPNAPI_KEY`
 * [ProxyCheck](https://proxycheck.io/): `PROXYCHECK_KEY` (Optional, It has free api quota for unregistered user)

# TODO
 * Remove `cymruwhois` and use own implementation.