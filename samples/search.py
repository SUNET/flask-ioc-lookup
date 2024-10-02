#!/usr/bin/env python3

from pprint import pprint
import requests
import sys

apitoken="<APITOKEN>"
endpoint="<IOC_LOOKUP_URL>"
data={"search": sys.argv[1] }

headers={"Accept": "application/json", "Content-Type": "application/json", "API-TOKEN": apitoken}
req = requests.post(url=endpoint, headers=headers, json=data)

pprint(req.json())
