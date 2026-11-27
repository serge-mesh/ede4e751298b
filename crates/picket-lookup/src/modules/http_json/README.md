# `http_json` lookup module

Reads a verdict from a JSON API (providers.md §5 `http_json`).

```json
{"method": "GET",
 "url": "https://api.example.net/v1/domain/{domain}",
 "headers": {"Authorization": "Bearer ${secret:key}"},
 "verdict": {"pointer": "/risk_score", "block_if": ">= 7.0", "clean_if": "< 4.0"}}
```

- `method`: `GET` (default) or `POST` (no body).
- `url`: `https` only, with `{domain}` after the host; the name is percent-encoded. No user info
  (credentials go in a header) and no fragment.
- `headers`: at most 32; values may reference secrets as `${secret:name}`, resolved by the
  `LookupClient` just before the call. `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`,
  `Upgrade` and `TE` belong to the client. `Accept: application/json` is added unless set.
- `verdict.pointer`: a JSON Pointer (RFC 6901). `block_if` (checked first) and `clean_if`: a
  numeric comparison (`<`, `<=`, `>`, `>=`, `==`, `!=` against a JSON number), string equality
  (`== "malicious"`, `!= "ok"`) or boolean equality (`== true`). A value of another type never
  matches. At least one of the two must be set.
- A Block's reason is the pointer and the `block_if` text (`/risk_score >= 7.0`); its score is the
  value when it is a number. The detail is `None`.

| Answer | Result |
|---|---|
| 200 | Parsed. A missing pointer or no matching comparison → Unknown; a body that isn't JSON → `Failed` |
| 404 | Unknown |
| 429 | `Rejected` with `Retry-After` (seconds or an HTTP date; none or unreadable → `None`): the provider pauses |
| 5xx, a timeout, a transport error, a body over 256 KiB | `Failed` (counts against health) |
| Any other status, redirects included | `Other` (doesn't count against health) |

Redirects are never followed (the `HttpClient` contract), so a credential never crosses one.
Error messages never quote the URL, a header or the body; the `LookupClient` also redacts secret
values from whatever a client's error says.

## Fixtures (`tests/`)

Response bodies in the shape of a typical risk-score API: a high score (`risk-high.json`), a low
one, one between the thresholds, one without the field, and a captive-portal HTML page served
with status 200.
