# flask-ioc-lookup

A simplified frontend for searching & reporting to MISP
Supports both a WebUI and a REST API

<img width="1100" alt="Screenshot IOC-Lookup" src="https://github.com/user-attachments/assets/421455ce-d410-4a34-b81b-f14b864ec2af">

## REST API howto guide

Perform a search:
```
% curl -s -H "Accept: application/json" \
    -H "Content-Type: application/json" \
    -H "API-TOKEN: <API-key>" -X POST \
    --data '{"search": "example.com"}' \
      https://<ENDPOINT.FQDN>/
```

Report an IOC:
```
curl -s -H "Accept: application/json" \
  -H "Content-Type: application/json" \
  -H "API-TOKEN: <API-key>" -X POST \
  --data '{"ioc": "test.test", "info": "some event info", "tlp": "tlp:green", "reference": "a comment", "by_proxy": false}' \
    https://<ENDPOINT.FQDN>/report
```
