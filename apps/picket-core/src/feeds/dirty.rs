//! Bundles a feed change made dirty (feeds.md §3 step 4: `feed.updated` → debounced bundle
//! builds and browser-list rewrites; core.md §3: debounced 10 s). The compiler (bundles.md §2)
//! registers a [`BuildSink`]; each dirty bundle reaches it once its feeds have been quiet for
//! [`DELAY`], and at the latest [`MAX_WAIT`] after the first change of a burst.
//!
//! The set is in memory: after a restart the compiler builds every bundle whose last version
//! records an older run for a member feed than that feed's newest run that changed entries
//! (bundles.md §2 "At start"), so nothing a restart loses goes unbuilt.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwapOption;

use crate::scheduler::Debouncer;

/// Quiet time before a dirty bundle is handed to the compiler.
pub const DELAY: Duration = Duration::from_secs(10);
/// The longest a bundle waits while its feeds keep changing.
pub const MAX_WAIT: Duration = Duration::from_secs(60);

/// What the compiler receives.
pub trait BuildSink: Send + Sync + 'static {
    /// `bundle` should be rebuilt: `feeds` changed since it was marked.
    fn build(&self, bundle: &str, feeds: Vec<String>);
}

/// The dirty bundles and their debouncer.
#[derive(Clone)]
pub struct Dirty {
    pending: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>>,
    sink: Arc<ArcSwapOption<Box<dyn BuildSink>>>,
    debounce: Debouncer<String>,
}

impl Default for Dirty {
    fn default() -> Self {
        Self::new(DELAY, MAX_WAIT)
    }
}

impl Dirty {
    pub fn new(delay: Duration, max_wait: Duration) -> Self {
        let pending: Arc<Mutex<BTreeMap<String, BTreeSet<String>>>> = Arc::default();
        let sink: Arc<ArcSwapOption<Box<dyn BuildSink>>> = Arc::default();
        let (p2, s2) = (pending.clone(), sink.clone());
        let debounce = Debouncer::with_max_wait(delay, max_wait, move |bundle: String| {
            let Some(sink) = s2.load_full() else {
                tracing::debug!(bundle = %bundle, "bundle dirty; no compiler registered yet");
                return;
            };
            let feeds = p2.lock().ok().and_then(|mut m| m.remove(&bundle));
            if let Some(feeds) = feeds {
                sink.build(&bundle, feeds.into_iter().collect());
            }
        });
        Self {
            pending,
            sink,
            debounce,
        }
    }

    /// Registers the compiler; bundles already pending are handed over at once.
    pub fn set_sink(&self, sink: Box<dyn BuildSink>) {
        self.sink.store(Some(Arc::new(sink)));
        let bundles: Vec<String> = self
            .pending
            .lock()
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        for b in bundles {
            self.debounce.trigger(b);
        }
    }

    /// Marks `bundles` dirty because `feed` changed. Bounded by the number of bundles.
    pub fn mark(&self, bundles: &[String], feed: &str) {
        for b in bundles {
            if let Ok(mut m) = self.pending.lock() {
                let feeds = m.entry(b.clone()).or_default();
                if feeds.len() < 4096 {
                    feeds.insert(feed.to_string());
                }
            }
            if !self.debounce.trigger(b.clone()) {
                tracing::warn!(bundle = %b, "too many dirty bundles at once");
            }
        }
    }

    /// The bundles waiting for a build, with the feeds that changed.
    pub fn pending(&self) -> BTreeMap<String, BTreeSet<String>> {
        self.pending.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Takes a bundle's pending mark (a compiler that builds on its own schedule).
    pub fn take(&self, bundle: &str) -> Option<BTreeSet<String>> {
        self.pending.lock().ok().and_then(|mut m| m.remove(bundle))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Builds = Arc<Mutex<Vec<(String, Vec<String>)>>>;
    struct Recorder(Builds);
    impl BuildSink for Recorder {
        fn build(&self, bundle: &str, feeds: Vec<String>) {
            self.0.lock().unwrap().push((bundle.to_string(), feeds));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn debounced_with_a_maximum_wait() {
        let d = Dirty::new(Duration::from_secs(10), Duration::from_secs(30));
        let got = Arc::new(Mutex::new(Vec::new()));
        d.set_sink(Box::new(Recorder(got.clone())));
        d.mark(&["block-common".into()], "f1");
        tokio::time::sleep(Duration::from_secs(5)).await;
        d.mark(&["block-common".into()], "f2");
        tokio::time::sleep(Duration::from_secs(8)).await;
        assert!(
            got.lock().unwrap().is_empty(),
            "still within 10 s of the last change"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(
            got.lock().unwrap().clone(),
            vec![(
                "block-common".to_string(),
                vec!["f1".to_string(), "f2".to_string()]
            )]
        );
        // A bundle whose feeds keep changing still builds within the maximum wait.
        for _ in 0..10 {
            d.mark(&["b2".into()], "f3");
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        assert!(got.lock().unwrap().iter().any(|(b, _)| b == "b2"));
    }

    #[tokio::test(start_paused = true)]
    async fn kept_until_a_compiler_registers() {
        let d = Dirty::new(Duration::from_secs(10), Duration::from_secs(30));
        d.mark(&["b".into()], "f");
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_eq!(d.pending().len(), 1);
        let got = Arc::new(Mutex::new(Vec::new()));
        d.set_sink(Box::new(Recorder(got.clone())));
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert_eq!(got.lock().unwrap().len(), 1);
        assert!(d.pending().is_empty());
    }
}
