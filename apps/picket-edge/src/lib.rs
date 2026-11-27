//! picket-edge: the DNS filtering resolver on the router (edge.md). This crate is the service
//! foundation: CLI, local config and state, identity and the pinned core session, convergence and
//! requests, log shipping and spool, metrics, conditions, admin socket, SSD and firmware checks,
//! neighbour watch, systemd notify/watchdog and the task supervisor; the DNS data path
//! ([`dns`]: listeners, profile choice, filtering, lookups, cache and upstreams); and the
//! activation and connectivity layer that plugs into the traits in [`hooks`] and the data path's
//! seams: bundle and verdict-set activation ([`bundles`]), the firewall client ([`firewall`]),
//! temporary allows and the bypass API ([`bypass`]), and the self-update handoff ([`release`]).

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "test code may cast freely; non-test code denies lossy casts"
    )
)]

pub mod admin;
pub mod allows;
pub mod bundles;
pub mod bypass;
pub mod cli;
pub mod clock;
pub mod commands;
pub mod conditions;
pub mod convergence;
pub mod core_client;
pub mod diag;
pub mod dns;
pub mod edge;
pub mod firewall;
pub mod firmware;
pub mod fsutil;
pub mod hooks;
pub mod identity;
pub mod local_config;
pub mod logs;
pub mod metrics;
pub mod neighbours;
pub mod paths;
pub mod release;
pub mod report;
pub mod service;
pub mod session;
pub mod state;
pub mod storage;
pub mod supervisor;
pub mod sysinfo;
pub mod systemd;
pub mod tls;
pub mod unifi;
pub mod update;
pub mod users;
