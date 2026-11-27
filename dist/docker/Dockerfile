# picket-core in a container, interim (pipelines.md §10). No image is published; build it
# locally from a release .deb placed next to this file:
#
#   docker build --build-arg DEB=picket-core_<version>_amd64.deb -t picket-core:<version> .
#
# (Without --build-arg, the .deb is expected as picket-core.deb.)
#
# Run with host networking only (a bridge breaks dnssec.source_ips, exempt_sources and the Host
# allowlist, README §3). The data directory on the host must belong to the image's user (UID and
# GID 7443, below) before the first start, or init can't write to it:
#
#   install -d -o 7443 -g 7443 -m 0750 <dir>
#   docker run --rm --network host -v <dir>:/var/lib/picket-core picket-core:<version> \
#       init --data-dir /var/lib/picket-core
#   docker run -d --name picket-core --network host -v <dir>:/var/lib/picket-core --read-only \
#       --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --memory 1g \
#       --restart on-failure:5 picket-core:<version>
FROM debian:13-slim

ARG DEB=picket-core.deb
# A fixed UID/GID, so the data directory's owner is the same across rebuilds.
ARG UID=7443
ARG GID=7443

RUN groupadd --system --gid "${GID}" picket-core \
 && useradd --system --uid "${UID}" --gid "${GID}" --home-dir /var/lib/picket-core --no-create-home \
        --shell /usr/sbin/nologin picket-core

COPY ${DEB} /tmp/picket-core.deb
RUN apt-get update \
 && apt-get install -y --no-install-recommends /tmp/picket-core.deb \
 && rm -rf /var/lib/apt/lists/* /tmp/picket-core.deb \
 && install -d -o picket-core -g picket-core -m 0750 /var/lib/picket-core

COPY --chmod=0755 picket-core-container /usr/local/bin/picket-core-container

# As the systemd unit sets them (security.md §4): two malloc arenas, SQLite spills to the data disk.
# The host must be NTP-synced (pipelines.md §10), and the container can't read its sync state
# (no timesyncd flag, no timedatectl), so PICKET_CLOCK_SYNCED=1 states it: retention's
# wall-clock deletes run (README §2 Clocks). Files core creates are 0600 whatever the umask.
ENV MALLOC_ARENA_MAX=2 \
    SQLITE_TMPDIR=/var/lib/picket-core/tmp \
    PICKET_CLOCK_SYNCED=1

USER picket-core
VOLUME ["/var/lib/picket-core"]
ENTRYPOINT ["/usr/local/bin/picket-core-container"]
CMD ["run", "--data-dir", "/var/lib/picket-core"]
