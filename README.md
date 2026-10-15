# flask-ioc-lookup

A simplified frontend for searching & reporting to MISP
Supports both a WebUI and a REST API

<img width="1100" alt="Screenshot IOC-Lookup" src="https://github.com/user-attachments/assets/421455ce-d410-4a34-b81b-f14b864ec2af">

## CSRF protection and configuration

`SECRET_KEY` must be set in the config file or in the environment variable `IOC_LOOKUP_SECRET_KEY`
(the environment variable takes precedence). Browser form POSTs need a CSRF token (included in the
forms) and a matching `Origin`/`Referer`. Set `TRUSTED_ORIGINS` if the app is served under another
origin than the one seen in the request. API clients must send a valid `API-TOKEN` header together with `Content-Type: application/json` (an API key with a form-encoded body is subject to the normal Origin and token checks). The Slack
endpoint is exempt from CSRF checks only when `SLACK_SIGNING_SECRET` (or the environment variable
`IOC_LOOKUP_SLACK_SIGNING_SECRET`, which takes precedence) is set and the request has a valid
`X-Slack-Signature` for a timestamp within 5 minutes. Without a signing secret Slack requests are rejected.

In production `TRUSTED_ORIGINS` should be set explicitly (for example `https://ioc.example.org`),
especially when TLS terminates at a proxy or load balancer that does not send `X-Forwarded-Proto`:
the Origin check is strict about scheme, so an `https` Origin will not match an `http` request seen
by the app. Rejections are logged with the expected and received origins.

The app trusts `X-Forwarded-Proto` and `X-Forwarded-For` from the proxy (`ProxyFix`), and the Docker
image starts gunicorn with `forwarded_allow_ips='*'`. Do not expose the app port directly: a client that
reaches it can forge these headers and defeat the scheme strictness of `TRUSTED_ORIGINS`. Only the reverse
proxy should reach the app, and `forwarded_allow_ips` should be set to the proxy's address. The session
token check still applies either way.

## Slack integration

The `/slack/ioc-lookup` endpoint is authenticated only by the Slack request signature
(`SLACK_SIGNING_SECRET`). The reverse proxy must not put it behind SSO, and should strip any
client-supplied `Remote-User` and `API-TOKEN` headers. Lookups run as a fixed, non-trusted identity
against the default MISP key; `REMOTE_USER` and `API-TOKEN` are never used for Slack requests.
The Slack rate limit is applied per Slack workspace (`team_id`) and defaults to `REQUEST_RATE_LIMIT`;
set the optional `SLACK_RATE_LIMIT` to give Slack its own limit. When it is hit Slack shows
`dispatch_failed`.

## Upgrade notes (breaking changes)

- `SECRET_KEY` (or `IOC_LOOKUP_SECRET_KEY`) is now required.
- All browser POSTs need the session CSRF token and a matching `Origin`/`Referer`.
- API clients must send `API-TOKEN` with `Content-Type: application/json` (`samples/search.py`,
  `search.sh` and `search.pl` already do). `REMOTE_USER`-only automation without `API-TOKEN` now gets 400/403.
- The Slack endpoint requires `SLACK_SIGNING_SECRET`; unsigned Slack requests are rejected.
- Set `TRUSTED_ORIGINS` in production, especially behind a proxy or load balancer that terminates TLS.
- `SESSION_COOKIE_SECURE` now defaults to true; set it to `false` for plain-HTTP development.
- `MAX_CONTENT_LENGTH` defaults to 1 MiB.
- The Slack endpoint now works when `DEBUG` is false (it previously returned 401 without a `REMOTE_USER`).
  Slack requests never use `REMOTE_USER` or `API-TOKEN`.
- Requests without valid credentials are now rate limited by IP before authentication.
- New optional `SLACK_RATE_LIMIT` (default: `REQUEST_RATE_LIMIT`). Consider raising it, since Slack shows
  `dispatch_failed` when a request is rate limited.
- `REQUEST_RATE_LIMIT` is now enforced before the CSRF checks, so rejected requests count against it too.
  It applies per route to every non-static route (previously only the decorated views).

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
