//! `alphamountain_threat_1000` (providers.md §3): alphaMountain's free community threat 1000
//! list, a CSV with the header `hostname,risk_score,more_info`.
//!
//! - **Config:** `{url?, min_risk_score: 7.0}` (default URL below). **File:** a provider has
//!   one, [`FILE`] (`community-threat-1000`), which `files` selects by default; its feed's id is
//!   the provider's id and its default name the provider's name (feeds.md §1). **Location:** the
//!   URL. **Lists files:** no.
//! - **Check:** a conditional GET as in `http` (`If-None-Match` / `If-Modified-Since`; a server
//!   without validators is compared by the CSV's SHA-256). On a change the CSV is converted into
//!   a `plain` file with one `hostname` per line for rows with `risk_score ≥ min_risk_score`; a
//!   cell holding CR or LF is rejected and counted. The feed's format must be `plain`, whose
//!   parser rejects and counts any line that isn't a name, IP or CIDR.
//! - `version` = the ETag, else the CSV's SHA-256; `updated_at` = `Last-Modified`, else the
//!   download time.
//! - Recommended modes: `dns: aggregate` (a rolling top 1,000), `ip: drop`, `browser: drop`.

pub mod csv;

use std::io::BufRead;

use jiff::Timestamp;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::client::Req;
use super::http::{HEAD_COST, bad_status, check_url, etag_of, last_modified_of};
use super::{ChangeTime, CheckError, CheckOutcome, Ctx, DownloadModule, FileCheck, LastRun, Normalized, ProviderCheck};

/// The list's published URL.
pub const DEFAULT_URL: &str = "https://files.alphamountain.ai/alphaMountain-community-threat-1000.csv";

/// A provider's one file: a fixed name (no file name is empty).
pub const FILE: &str = "community-threat-1000";

/// The refusal of any other file.
fn one_file() -> String {
    format!("an alphamountain_threat_1000 provider has one file, {FILE:?}")
}

fn default_min() -> f64 {
    7.0
}

/// A provider's settings.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The CSV's `https://` URL; null = alphaMountain's published list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Rows with a `risk_score` at or above this are kept (0–10).
    #[serde(default = "default_min")]
    pub min_risk_score: f64,
}

/// What the file keeps between checks.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct State {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
    /// SHA-256 of the CSV.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csv_sha256: Option<String>,
    /// The minimum the last conversion used: a new minimum converts again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_risk_score: Option<f64>,
    /// The last conversion's counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub csv: Option<csv::CsvStats>,
}

#[derive(Default)]
pub struct Module;

fn url_of(c: &Config) -> &str {
    c.url.as_deref().unwrap_or(DEFAULT_URL)
}

impl Module {
    /// The one file's check.
    async fn check_one(&self, ctx: &Ctx, cfg: &Value, last: Option<&LastRun>) -> Result<CheckOutcome, CheckError> {
        let c: Config =
            serde_json::from_value(cfg.clone()).map_err(|e| CheckError::Failed(anyhow::anyhow!("invalid config: {e}")))?;
        let url = check_url(url_of(&c)).map_err(|e| CheckError::Failed(anyhow::anyhow!(e)))?;
        let st: State = last
            .and_then(|l| serde_json::from_value(l.state.clone()).ok())
            .unwrap_or_default();
        let same_min = st.min_risk_score == Some(c.min_risk_score);
        let mut req = Req::get(url).header("accept", "text/csv, text/plain;q=0.9, */*;q=0.1")?;
        if last.is_some() && same_min {
            if let Some(e) = &st.etag {
                req = req.header("if-none-match", e)?;
            }
            if let Some(lm) = &st.last_modified {
                req = req.header("if-modified-since", lm)?;
            }
        }
        let resp = ctx.http.send(req).await?;
        if resp.status == http::StatusCode::NOT_MODIFIED && last.is_some() && same_min {
            return Ok(CheckOutcome::Unchanged {
                state: None,
                observed: vec![],
                bytes: HEAD_COST,
                method: "conditional",
            });
        }
        if resp.status != http::StatusCode::OK {
            return Err(bad_status(&resp));
        }
        let etag = etag_of(&resp);
        let lm = last_modified_of(&resp);
        let csv_file = ctx.stage(resp).await?;
        let bytes = csv_file.size() + HEAD_COST;
        let csv_sha = csv_file.sha256().to_string();
        let mut new_state = State {
            etag: etag.clone(),
            last_modified: lm.as_ref().map(|(s, _)| s.clone()),
            csv_sha256: Some(csv_sha.clone()),
            min_risk_score: Some(c.min_risk_score),
            csv: st.csv.clone(),
        };
        if last.is_some() && same_min && st.csv_sha256.as_deref() == Some(csv_sha.as_str()) {
            return Ok(CheckOutcome::Unchanged {
                state: Some(serde_json::to_value(&new_state).unwrap_or(Value::Null)),
                observed: vec![],
                bytes,
                // The whole CSV came back: a full download.
                method: "full",
            });
        }
        // Convert into a plain file, off the async threads.
        let mut out = ctx.stage_sync().map_err(|e| CheckError::Failed(anyhow::anyhow!("cannot stage the list: {e}")))?;
        let min = c.min_risk_score;
        let path = csv_file.path().to_path_buf();
        let (plain, stats) = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
            let reader = std::io::BufReader::with_capacity(64 * 1024, std::fs::File::open(&path)?);
            let stats = convert_into(reader, min, &mut out)?;
            Ok((out.finish()?, stats))
        })
        .await
        .map_err(|e| CheckError::Failed(anyhow::anyhow!("the conversion failed: {e}")))?
        .map_err(|e| CheckError::Failed(anyhow::anyhow!("cannot convert the CSV: {e}")))?;
        drop(csv_file);
        if stats.rejected_cells > 0 || stats.bad_rows > 0 {
            tracing::info!(provider = %ctx.provider_id, rejected_cells = stats.rejected_cells, bad_rows = stats.bad_rows, "alphaMountain CSV rows rejected");
        }
        new_state.csv = Some(stats);
        let exact: Option<Timestamp> = lm.as_ref().map(|(_, t)| *t);
        let change_times = match (exact, ctx.last_ok) {
            (Some(t), _) => vec![ChangeTime::Exact(t)],
            (None, Some(lo)) => vec![ChangeTime::Interval { lo, hi: ctx.now }],
            (None, None) => vec![],
        };
        Ok(CheckOutcome::Changed {
            updated_at: exact.unwrap_or(ctx.now),
            version: etag.unwrap_or(csv_sha),
            state: serde_json::to_value(&new_state).unwrap_or(Value::Null),
            change_times,
            file: plain,
            bytes,
            method: "conditional",
        })
    }
}

#[async_trait::async_trait]
impl DownloadModule for Module {
    fn id(&self) -> &'static str {
        "alphamountain_threat_1000"
    }

    fn config_schema(&self) -> schemars::Schema {
        super::schema_of::<Config>()
    }

    fn location(&self, cfg: &Value) -> String {
        cfg.get("url").and_then(Value::as_str).unwrap_or(DEFAULT_URL).to_string()
    }

    fn check_file(&self, _cfg: &Value, file: &str, _pattern: bool) -> Result<(), String> {
        if file == FILE { Ok(()) } else { Err(one_file()) }
    }

    fn default_files(&self) -> Vec<(String, Value)> {
        vec![(FILE.to_string(), serde_json::json!({"format": "plain"}))]
    }

    fn fixed_file(&self) -> Option<&'static str> {
        Some(FILE)
    }

    fn normalize_config(&self, cfg: &Value) -> Result<Normalized, String> {
        let c: Config = super::parse_config(cfg)?;
        check_url(url_of(&c))?;
        if !(0.0..=10.0).contains(&c.min_risk_score) {
            return Err("min_risk_score must be between 0 and 10".into());
        }
        Ok(Normalized {
            config: cfg.clone(),
            notice: None,
        })
    }

    async fn check(
        &self,
        ctx: &Ctx,
        cfg: &Value,
        _state: Option<&Value>,
        feeds: &[FileCheck],
        _select: &[String],
    ) -> Result<ProviderCheck, CheckError> {
        let mut files = Vec::with_capacity(feeds.len());
        for f in feeds {
            let out = if f.file == FILE {
                self.check_one(ctx, cfg, f.last.as_ref()).await
            } else {
                Err(CheckError::Failed(anyhow::anyhow!(one_file())))
            };
            files.push((f.file.clone(), out));
        }
        Ok(ProviderCheck {
            state: Value::Object(Default::default()),
            files,
            listing: None,
        })
    }
}

/// Writes the plain file: a header comment with the counts, then one hostname per line.
fn convert_into<R: BufRead>(
    reader: R,
    min: f64,
    out: &mut super::ctx::SyncStageWriter,
) -> std::io::Result<csv::CsvStats> {
    out.write(b"# alphaMountain community threat 1000, converted by picket\n")?;
    let stats = csv::convert(reader, min, |h| {
        out.write(h.as_bytes())?;
        out.write(b"\n")
    })?;
    out.write(
        format!(
            "# rows {}, kept {} (risk_score >= {min}), below {}, bad rows {}, rejected cells {}\n",
            stats.rows, stats.kept, stats.below, stats.bad_rows, stats.rejected_cells
        )
        .as_bytes(),
    )?;
    Ok(stats)
}

#[cfg(test)]
mod tests;
