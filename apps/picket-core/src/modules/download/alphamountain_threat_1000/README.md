# `alphamountain_threat_1000` download provider

alphaMountain's free [community threat 1000](https://www.alphamountain.ai/free-threat-intelligence-feeds/)
list (providers.md §3): `https://files.alphamountain.ai/alphaMountain-community-threat-1000.csv`,
header `hostname,risk_score,more_info`.

- **Config:** `{url?, min_risk_score: 7.0}`.
- **File:** one, `community-threat-1000`, which `files` selects by default; its feed's id is the
  provider's id and its default name the provider's name.
- **Check:** a conditional GET as in `http`. On a change the CSV is converted into a `plain`
  file with one hostname per line for rows with `risk_score ≥ min_risk_score`; a cell with CR
  or LF is rejected and counted (the counts are in the run's provider state and the file's
  trailing comment). The feed's format must be `plain`; its parser checks every line.
- `version`: the ETag, else the CSV's SHA-256; `updated_at`: `Last-Modified`.
- Recommended modes: `dns: aggregate`, `ip: drop`, `browser: drop`.

`tests/` holds a recorded CSV (`list.csv`) and runs the provider against a local HTTPS server.
