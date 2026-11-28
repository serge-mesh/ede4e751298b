# `github` download provider

A file in a GitHub repository, followed on a branch (providers.md §3).

- **Config:** `{url}` or `{owner, repo, branch?, path}`, plus an optional read-only `token`
  (`${secret:name}`). URL forms: `raw.githubusercontent.com/<o>/<r>/<branch>/<path>`, the
  file's page `github.com/<o>/<r>/blob/<branch>/<path>`, and
  `cdn.jsdelivr.net/gh/<o>/<r>@latest/<path>` (a save converts the latter to owner, repo and
  path on the default branch). Tags are never followed; `<o>.github.io` lists are `http` feeds.
- **Check:** one git protocol v2 `ls-refs` POST to `github.com/<o>/<r>.git/git-upload-pack`,
  shared for 2 minutes by every feed on the same repository and branch. A moved head asks the
  commits API (exact change times) and the contents API (the blob SHA); a new blob is downloaded
  by commit from `raw.githubusercontent.com` and checked against git's blob hash.
- `version`: the blob SHA; `updated_at`: the newest commit time touching the path;
  `state`: `{head, blob}`; sibling group `github:<o>/<r>`.
- **Rate limits:** 429, or 403 with a rate-limit header, pauses every `github` check until
  `Retry-After` or `x-ratelimit-reset`, kept whole past an hour (held to a week against a bad
  header). The pause survives a restart.
- `history()` reads the commits API back 60 days or 20 changes, skipping root commits.

`tests/` holds a recorded `ls-refs` answer and runs the provider against a local fake of
github.com, api.github.com and raw.githubusercontent.com.
