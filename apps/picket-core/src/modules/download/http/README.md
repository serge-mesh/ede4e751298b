# `http` download provider

Any list on an HTTPS URL (providers.md §3).

- **Config:** `{url, headers?, date_line_regex?}`. Headers other than `Accept`,
  `Accept-Language`, `Cache-Control`, `Content-Type`, `Pragma` and `User-Agent` take only
  `${secret:name}` references and go to the URL's host only, never across a redirect.
- **File:** one, `response` (what the URL answers): a provider is one URL, its one feed has the
  provider's id and, by default, its name. Editing `url` points the feed elsewhere.
- **First check** probes: a plain GET, the same GET with `If-None-Match` / `If-Modified-Since`
  (does the server answer `304`?), and `Range: bytes=0-4095` (does it answer `206`?). The result
  is `state.method`: `conditional`, `range` or `full`.
- **Checks** use that rung: a conditional GET; or the first 4 KiB compared by total size, date
  line and hash, then a full GET when any differ (and at least once a day); or a full GET
  compared by SHA-256. A body identical to the last run's is `Unchanged`.
- **Change time:** `Last-Modified`, else a header date line (`! Last modified: …`,
  `# Updated : …`, or `date_line_regex`'s first group), else an interval.
- `version`: the ETag, else the body's SHA-256. Sibling group: the host.

`tests/` runs the provider against a local HTTPS server: each rung, 304s, ETags, redirects,
oversized, slow, gzip and HTML bodies.
