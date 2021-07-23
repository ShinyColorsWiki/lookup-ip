LookUp IP
=========
This used for blocking ip range which has bad ip like vpn, proxy, hosting.

Formatting for Info block: `[ASNumber] [AS Owner], [Country]`

Usage
=====
```sh
$ pipenv install
# Alternatively, $ pip install python-dotenv cymruwhois
$ pipenv run python lookup.py
# Alternatively, $ python lookup.py
Request: 8.8.8.8

IP: 8.8.8.8
Reputation: BAD (IPHub)
CIDR: 8.8.8.0/24
Info: AS15169 GOOGLE, US

Request:
...
```


TODO
====
 * Remove `cymruwhois` and use own implementation.