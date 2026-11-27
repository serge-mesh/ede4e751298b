# picket-core packaging

- `picket-core.service`: the service (`run`), hardened as security.md §4 sets out, with
  `RestartPreventExitStatus=78` so a missing marker, a failed migration or a database newer than
  the release leaves core stopped (core.md §13, storage.md §5).
- `picket-core-init.service`: a oneshot ordered before it that runs `init` while the data
  directory has no marker (`ConditionPathExists=!`). The first admin password is in
  `/var/lib/picket-core/initial-password` (0600); the unit sends `init`'s output to `/dev/null`
  so the password never reaches the journal.
- `debian/postinst`: creates the `picket-core` system user and `/var/lib/picket-core` (0750).
  Core sets its own umask (077), so its databases and keys are 0600 however it is started, and
  one process at a time holds the data directory (an `flock` on it): `passwd` or `edges add`
  against a running core exits 75 and changes nothing.
- Retention's wall-clock deletes wait until the clock is synchronised (systemd-timesyncd's flag
  or `timedatectl`'s `NTPSynchronized`; README §2 Clocks).
- The `.deb` is built with `cargo deb -p picket-core` (metadata in `apps/picket-core/Cargo.toml`).
  The release pipeline adds the edge release of the same version under
  `/usr/share/picket-core/edge/<version>/` (core.md §5, pipelines.md §4).
