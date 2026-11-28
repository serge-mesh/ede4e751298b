//! A build's commit (bundles.md §2 step 6; storage.md §3): one writer transaction applies the
//! build's ops to `bundle_keys`, renumbers the rows of split or merged shards, replaces the runs of
//! changed IP shards, rewrites the shard bookkeeping, registers the version's blobs, inserts the
//! `bundle_versions` row (with `feed_runs_json`), records the build in `bundle_builds`, applies the
//! guardrail alerts and empties the work tables. So the version, the materialised state and the
//! alerts follow one another in commit order, or none of them happens. A build whose setup came
//! before a config restore's commit commits nothing (core.md §2): it read pre-restore entries.
//! Then the edges' config objects are re-rendered (`changed`), and the browser lists and
//! warnings follow.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use picket_bundle::hash::KeyHash;
use picket_rules::compile::Part;
use rusqlite::params;
use serde_json::json;

use super::build::{Ctx, Mode};
use super::store::{self, part_text};
use crate::alerts::{Changes, RaiseSpec, Severity};
use crate::state::SharedState;

/// Commits a finished build.
pub async fn commit(state: &SharedState, bundle: &str, ctx: Ctx, started: std::time::Instant) -> Result<()> {
    let edge = ctx.spec.has_edge_bundle();
    let now = crate::util::now_ts();
    let b = bundle.to_string();
    let alerts = state.alerts.clone();
    let members = ctx.spec.members.clone();
    // The feeds and rule types whose rules this bundle compiles as blocks: the only ones a
    // public-suffix hit can come from (#49).
    let psl_members: super::guard::PslMembers =
        if ctx.spec.action == crate::config::model::BundleAction::Block {
            ctx.spec
                .members
                .iter()
                .map(|m| {
                    let types = ctx
                        .spec
                        .compiled_types(m)
                        .iter()
                        .map(|t| t.as_str().to_owned())
                        .collect();
                    (m.feed.clone(), types)
                })
                .collect()
        } else {
            Vec::new()
        };
    let runs_json = super::spec::runs_json(&ctx.runs);
    let def_hash = ctx.spec.def_hash.clone();
    // Replay reads each member feed as this version took it (core.md §6 step 1).
    let def_json = crate::logs::replay::definition_json(&ctx.spec);
    let mode = ctx.mode;
    let prev_head = ctx.prev.as_ref().map(|p| p.head_id.clone());
    let findings = ctx.findings.clone();
    let ips = ctx.ips.clone().unwrap_or_default();
    let mut st = ctx.state.clone();
    st.last_build_at = Some(now.clone());
    let mut assembly = ctx.assembly;
    let compact_requests = assembly
        .as_mut()
        .map(|a| std::mem::take(&mut a.compact_requests))
        .unwrap_or_default();
    let (head, head_blob) = match &assembly {
        Some(a) => (a.head.clone(), a.head_blob.clone()),
        None => (None, None),
    };
    if edge && head.is_none() {
        return Err(anyhow!("the build assembled no head"));
    }
    // A new `patterns.bin` or `rich.json` changes DNS answers beyond the changed keys (bundles.md
    // §8 Builds: it schedules the pruned lists' DNS-change rebuild).
    let segments_changed = match (&head, ctx.prev.as_ref()) {
        (Some(h), Some(p)) => h.segments != p.head.segments,
        (Some(_), None) => true,
        (None, _) => false,
    };
    let head_id = head_blob.as_ref().map(|h| h.id.clone());
    let head_id2 = head_id.clone();
    if let Some(a) = &assembly {
        st.patterns_blob = a.patterns_blob.clone();
        st.patterns_edge_memory = a.patterns_edge_memory;
    }
    if let Some(p) = &ctx.patterns {
        st.patterns_digest = Some(p.digest.clone());
    }
    let (hot_keys, cold_keys) = assembly.as_ref().map_or((0, 0), |a| {
        a.shard_rows
            .iter()
            .fold((0u64, 0u64), |(h, c), ((p, _), r)| match p {
                Part::Hot => (h + r.keys, c),
                Part::Cold => (h, c + r.keys),
            })
    });
    let stats = json!({
        "mode": mode.as_str(),
        "reasons": ctx.request.reasons,
        "edge_mem_bytes": assembly.as_ref().map_or(0, |a| a.edge_mem_bytes),
        "overlay_bytes": assembly.as_ref().map_or(0, |a| a.overlay_bytes),
        "hot_keys": hot_keys,
        "cold_keys": cold_keys,
        "hot_bytes": assembly.as_ref().map_or(0, |a| a.shard_rows.iter().filter(|((p, _), _)| *p == Part::Hot).map(|(_, r)| r.mem_bytes).sum::<u64>()),
        "cold_filter_bytes": assembly.as_ref().map_or(0, |a| a.shard_rows.iter().filter(|((p, _), _)| *p == Part::Cold).map(|(_, r)| r.mem_bytes).sum::<u64>()),
        "cold_page_bytes": assembly.as_ref().map_or(0, |a| a.shard_rows.values().map(|r| r.disk_bytes).sum::<u64>()),
        "ip_runs": assembly.as_ref().map_or(0, |a| a.ip_rows.values().map(|r| r.runs).sum::<u64>()),
        "ip_shards": assembly.as_ref().map_or(0, |a| a.ip_rows.len()),
        "shards": assembly.as_ref().map_or(0, |a| a.shard_rows.keys().filter(|(p, _)| *p == Part::Hot).count()),
        "cold_shards": assembly.as_ref().map_or(0, |a| a.shard_rows.keys().filter(|(p, _)| *p == Part::Cold).count()),
        "patterns": ctx.patterns.as_ref().map_or(0, |p| p.count),
        "patterns_edge_memory": assembly.as_ref().map_or(0, |a| a.patterns_edge_memory),
        "rich_rules": assembly.as_ref().map_or(0, |a| a.rich_rules),
        "changed_keys": ctx.stats.changed_keys,
        "keys_added": ctx.stats.keys_added,
        "keys_deleted": ctx.stats.keys_deleted,
        "keys_changed": ctx.stats.keys_changed,
        "moves": ctx.stats.moves,
        "pruned": ctx.stats.pruned,
        "entries_read": ctx.stats.entries_read,
        "delta_bytes": assembly.as_ref().map_or(0, |a| a.delta_bytes),
        "base_bytes": assembly.as_ref().map_or(0, |a| a.base_bytes),
        "badfiltered": ctx.counts.badfiltered,
        "entity_refused": ctx.counts.entity_refused,
        "unlinked_entities": ctx.counts.unlinked,
        "unreadable_rows": ctx.bad_rows,
        "exact_rewrite_order": ctx.wide.exact_orders,
        "wide_digest": ctx.wide_digest,
        "duration_ms": picket_api::duration::as_millis_u64(started.elapsed()),
        "findings_dropped": findings.dropped,
    });
    let stats_s = stats.to_string();
    let state_s = serde_json::to_string(&st).unwrap_or_else(|_| "{}".into());
    let cold_capable = ctx.spec.cold_capable();
    let hot_over = st.tier.as_ref().is_some_and(|t| t.hot_tier_over);
    let hot_max = ctx.spec.hot_max_mib;
    // A build that just applied new cutoffs never asks for another re-rank (no loop).
    let reranked = ctx.request.rerank;
    let touched_browser = ctx.touched.browser;
    let touched_ip = ctx.touched.ip;
    let changed_keys =
        ctx.stats.keys_added + ctx.stats.keys_deleted + ctx.stats.keys_changed + ctx.stats.moves;
    let generation = ctx.generation;
    let gate = state.restore.clone();
    // Tests: a restore that commits here, after the step checked the generation, is caught by
    // the check inside the write.
    if let Some(pause) = state.compiler.take_commit_pause() {
        pause.await;
    }
    let committed = state
        .db
        .write(move |c| {
            let tx = c.transaction()?;
            // A config restore committed since the build read its feeds (core.md §2): nothing of
            // it is committed, only its work rows go. Checked on the writer, so it is ordered
            // with the restore's own commit.
            if !gate.is_current(generation) {
                store::clear_work(&tx, &b)?;
                tx.commit()?;
                return Ok::<_, anyhow::Error>(None);
            }
            let mut ch = Changes::default();
            // Keys: a fresh build's staged keys replace the bundle's (README §2 Restarts: readers
            // never see a partial table); other builds apply their ops.
            if mode == Mode::Fresh {
                tx.execute("DELETE FROM bundle_keys WHERE bundle_id = ?1", [&b])?;
                tx.execute(
                    "INSERT INTO bundle_keys(bundle_id, part, shard, hash128, key, value, tier, rank_at)
                     SELECT bundle_id, part, shard, hash128, key, value, tier, rank_at FROM bundle_build_fresh
                     WHERE bundle_id = ?1",
                    [&b],
                )?;
                tx.execute("DELETE FROM bundle_ip_ranges WHERE bundle_id = ?1", [&b])?;
            } else {
                tx.execute(
                    "DELETE FROM bundle_keys WHERE bundle_id = ?1 AND key IN (SELECT key FROM bundle_build_ops WHERE bundle_id = ?1)",
                    [&b],
                )?;
                tx.execute(
                    "INSERT INTO bundle_keys(bundle_id, part, shard, hash128, key, value, tier, rank_at)
                     SELECT bundle_id, new_part, new_shard, hash128, key, new_value, tier, rank_at FROM bundle_build_ops
                     WHERE bundle_id = ?1 AND new_part IS NOT NULL",
                    [&b],
                )?;
            }
            let mut published = None;
            if let (Some(a), Some(head), Some(hb)) = (&assembly, &head, &head_blob) {
                // Rows of split or merged shards take their new shard numbers.
                for pp in [a.hot.as_ref(), a.cold.as_ref()].into_iter().flatten() {
                    let pt = part_text(pp.part);
                    for old in &pp.renumber {
                        let rows: Vec<(i64, Vec<u8>)> = {
                            let mut st = tx.prepare_cached(
                                "SELECT rowid, hash128 FROM bundle_keys WHERE bundle_id = ?1 AND part = ?2 AND shard = ?3",
                            )?;
                            st.query_map(params![b, pt, *old as i64], |r| Ok((r.get(0)?, r.get(1)?)))?
                                .collect::<rusqlite::Result<_>>()?
                        };
                        let mut up = tx.prepare_cached("UPDATE bundle_keys SET shard = ?1 WHERE rowid = ?2")?;
                        for (rowid, h) in rows {
                            let hash = KeyHash(<[u8; 16]>::try_from(h.as_slice()).map(u128::from_be_bytes).unwrap_or(0));
                            up.execute(params![pp.dir.shard_of(hash) as i64, rowid])?;
                        }
                    }
                }
                // A part that is gone (an emptied cold part).
                if a.cold.is_none() {
                    tx.execute("DELETE FROM bundle_keys WHERE bundle_id = ?1 AND part = 'cold'", [&b])?;
                }
                // IP runs of changed shards (the IP pass left them in bundle_build_ip_runs).
                for id in ips.changed.keys() {
                    tx.execute(
                        "DELETE FROM bundle_ip_ranges WHERE bundle_id = ?1 AND ip_shard = ?2",
                        params![b, id.to_string()],
                    )?;
                    tx.execute(
                        "INSERT INTO bundle_ip_ranges(bundle_id, ip_shard, \"first\", \"last\", value)
                         SELECT bundle_id, ip_shard, \"first\", \"last\", value FROM bundle_build_ip_runs
                         WHERE bundle_id = ?1 AND ip_shard = ?2",
                        params![b, id.to_string()],
                    )?;
                }
                // Shard bookkeeping.
                tx.execute("DELETE FROM bundle_shards WHERE bundle_id = ?1", [&b])?;
                let mut ins = tx.prepare_cached(
                    "INSERT INTO bundle_shards(bundle_id, part, shard, prefix, prefix_bits, base_blake3, base_seq, seq,
                        overlay_bytes, created_at, keys, mem_bytes, disk_bytes, overlay_entries, deltas)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                )?;
                let per = crate::util::sat_i64(picket_bundle::overlay::KEY_OVERLAY_BYTES_PER_ENTRY);
                for (part, dir, refs) in [
                    (Part::Hot, &head.shard_dir, &head.shards),
                    (Part::Cold, &head.cold_shard_dir, &head.cold_shards),
                ] {
                    for e in dir {
                        let Some(r) = refs.iter().find(|r| r.shard == e.shard) else { continue };
                        let row = a.shard_rows.get(&(part, e.shard)).cloned().unwrap_or_default();
                        ins.execute(params![
                            b,
                            part_text(part),
                            e.shard as i64,
                            e.prefix as i64,
                            i64::from(e.prefix_bits),
                            r.base,
                            r.base_seq,
                            r.seq,
                            crate::util::sat_i64(row.overlay_entries).saturating_mul(per),
                            row.created_at,
                            row.keys,
                            row.mem_bytes,
                            row.disk_bytes,
                            row.overlay_entries,
                            row.deltas,
                        ])?;
                    }
                }
                tx.execute("DELETE FROM bundle_ip_shards WHERE bundle_id = ?1", [&b])?;
                let mut ins = tx.prepare_cached(
                    "INSERT INTO bundle_ip_shards(bundle_id, ip_shard, base_blake3, base_seq, seq, overlay_bytes, created_at,
                        runs, mem_bytes, overlay_entries, deltas) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )?;
                for r in &head.ip_shards {
                    let row = a.ip_rows.get(&r.ip_shard).cloned().unwrap_or_default();
                    let per = if r.ip_shard.is_v4() {
                        super::assemble::IP4_OVERLAY_BYTES
                    } else {
                        super::assemble::IP6_OVERLAY_BYTES
                    };
                    ins.execute(params![
                        b,
                        r.ip_shard.to_string(),
                        r.base,
                        r.base_seq,
                        r.seq,
                        crate::util::sat_i64(row.overlay_entries.saturating_mul(per)),
                        row.created_at,
                        row.runs,
                        row.mem_bytes,
                        row.overlay_entries,
                        row.deltas,
                    ])?;
                }
                // The version, unless it is the current one again (a forced build with no change).
                // A version already stored (a forced build with no change, or the same state
                // built again after a retirement) isn't inserted twice.
                let known: bool = tx
                    .query_row(
                        "SELECT 1 FROM bundle_versions WHERE bundle_id = ?1 AND head_id = ?2",
                        params![b, hb.id],
                        |_| Ok(()),
                    )
                    .is_ok();
                if prev_head.as_deref() != Some(hb.id.as_str()) && known {
                    tx.execute(
                        "UPDATE bundle_versions SET superseded_at = NULL, last_used_at = ?3 WHERE bundle_id = ?1 AND head_id = ?2",
                        params![b, hb.id, now],
                    )?;
                    published = Some(hb.id.clone());
                }
                if prev_head.as_deref() != Some(hb.id.as_str()) && !known {
                    let sizes: BTreeMap<&str, u64> = a.written.iter().map(|(i, s)| (i.as_str(), *s)).collect();
                    for id in &a.named {
                        crate::blobs::register_named(
                            &tx,
                            id,
                            crate::blobs::kind::BUNDLE,
                            sizes.get(id.as_str()).copied().unwrap_or(0),
                        )?;
                        tx.execute(
                            "INSERT OR IGNORE INTO bundle_version_blobs(bundle_id, head_id, blake3) VALUES (?1, ?2, ?3)",
                            params![b, hb.id, id],
                        )?;
                    }
                    tx.execute(
                        "INSERT INTO bundle_versions(bundle_id, head_id, heads_json, feed_runs_json, definition_hash,
                            published_at, stats_json, last_used_at, definition_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?6, ?8)",
                        params![
                            b,
                            hb.id,
                            String::from_utf8_lossy(&hb.bytes),
                            runs_json,
                            def_hash,
                            now,
                            stats_s,
                            def_json
                        ],
                    )?;
                    if let Some(p) = &prev_head {
                        tx.execute(
                            "UPDATE bundle_versions SET superseded_at = ?3 WHERE bundle_id = ?1 AND head_id = ?2
                               AND superseded_at IS NULL",
                            params![b, p, now],
                        )?;
                    }
                    published = Some(hb.id.clone());
                }
            }
            tx.execute(
                "INSERT INTO bundle_builds(bundle_id, feed_runs_json, definition_hash, head_id, built_at, status, error,
                    failed_at, stats_json, state_json) VALUES (?1, ?2, ?3, ?4, ?5, 'ok', NULL, NULL, ?6, ?7)
                 ON CONFLICT(bundle_id) DO UPDATE SET feed_runs_json = ?2, definition_hash = ?3, head_id = ?4,
                    built_at = ?5, status = 'ok', error = NULL, failed_at = NULL, stats_json = ?6, state_json = ?7",
                params![b, runs_json, def_hash, head_id2, now, stats_s, state_s],
            )?;
            // Alerts.
            super::guard::apply(&tx, &alerts, &b, &members, &psl_members, &findings, &mut ch)?;
            alerts.resolve_in(
                &tx,
                &format!("bundle_build_failed:{b}"),
                Some(&json!({"built": now})),
                &mut ch,
            )?;
            let hot_key = format!("bundle_over_budget:hot:{b}");
            if cold_capable && hot_over {
                if !crate::alerts::Alerts::is_open_in(&tx, &hot_key)? {
                    let spec = RaiseSpec::new(
                        "bundle_over_budget",
                        Severity::Warning,
                        hot_key,
                        format!("Bundle {b}: its hot-tier keys alone pass hot_max_mib"),
                        json!({"bundle": b, "hot_max_mib": hot_max, "hot_keys": hot_keys,
                               "note": "every intelligent-tiering key went cold; the version is published"}),
                    )
                    .bundle(b.clone());
                    alerts.raise_in(&tx, &spec, &mut ch)?;
                }
            } else {
                alerts.resolve_in(&tx, &hot_key, Some(&json!({"cleared": now})), &mut ch)?;
            }
            // The changed keys, for the browser lists' DNS-change tracking (bounded).
            let changed: Option<Vec<String>> = {
                let mut st = tx.prepare(
                    "SELECT key FROM bundle_build_ops WHERE bundle_id = ?1
                       AND (old_part IS NOT new_part OR old_value IS NOT new_value) LIMIT ?2",
                )?;
                let v: Vec<String> = st
                    .query_map(params![b, crate::lists::MAX_CHANGED_KEYS + 1], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?;
                (v.len() <= crate::lists::MAX_CHANGED_KEYS && mode != Mode::Fresh).then_some(v)
            };
            store::clear_work(&tx, &b)?;
            tx.commit()?;
            alerts.committed(&ch);
            Ok(Some((ch, published, changed)))
        })
        .await?;
    let Some((ch, published, changed)) = committed else {
        tracing::info!(bundle = %bundle, "bundle build ended by a config restore; it builds again");
        super::rebuild_after_restore(state, bundle);
        return Ok(());
    };
    state.alerts.announce(ch);
    tracing::info!(bundle = %bundle, mode = mode.as_str(), head = ?head_id.as_deref().map(picket_api::ids::short_id),
        changed = changed_keys, ms = picket_api::duration::as_millis_u64(started.elapsed()), "bundle built");
    if let Ok(data) = serde_json::to_value(crate::web::events::BundleVersionEvent {
        bundle: bundle.to_string(),
        head: head_id.clone(),
        published: published.is_some(),
        stats: serde_json::to_value(&stats).unwrap_or_default(),
    }) {
        state.events.send("bundle_version", data);
    }
    if published.is_some() {
        state.edges.publisher.trigger(None);
    }
    // Other bundles' overlays this build found largest on an edge past its overlay budget: their
    // compaction builds (bundles.md §5; core.md §3 P2).
    for (other, parts) in compact_requests {
        state.compiler.request(
            state,
            &other,
            super::build::Request {
                reasons: [format!("overlay budget (found by bundle {bundle}'s build)")].into(),
                compact: parts,
                ..super::build::Request::default()
            },
            crate::scheduler::Priority::P2,
        );
    }
    // A build that pushed the hot part past hot_max_mib re-ranks (bundles.md §2 Tiering).
    if let Some(mib) = hot_max
        && cold_capable
        && hot_keys.saturating_mul(super::tier::HOT_BYTES_PER_KEY)
            > u64::from(mib).saturating_mul(1024 * 1024)
        && !hot_over
        && !reranked
    {
        state.compiler.request(
            state,
            bundle,
            super::build::Request {
                reasons: ["hot part past hot_max_mib".to_string()].into(),
                rerank: true,
                ..super::build::Request::default()
            },
            crate::scheduler::Priority::P2,
        );
    }
    let changed = if changed_keys == 0 && published.is_none() {
        Some(Vec::new())
    } else {
        changed
    };
    state
        .lists
        .bundle_built(
            state,
            bundle,
            touched_browser,
            changed.as_deref(),
            segments_changed,
        )
        .await;
    // A definition change (a feed may have left) or changed IP rules (one may have gone)
    // re-checks the block bundle's open warnings (bundles.md §3).
    super::warn::bundle_built(state, bundle, mode != Mode::Incremental || touched_ip).await;
    Ok(())
}
