use bytes::Bytes;
use hyper::body::{Body, Frame};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::time::{interval, Interval};

/// Global Deep Tarpit Economy metrics for Prometheus & HUD telemetry.
pub static GLOBAL_TARPIT_SECONDS_DRAINED: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_TARPIT_BYTES_DRAINED: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_TARPIT_ACTIVE_SOCKETS: AtomicUsize = AtomicUsize::new(0);
pub static GLOBAL_JSON_SINKS_ACTIVE: AtomicUsize = AtomicUsize::new(0);
pub static GLOBAL_HTML_SINKS_ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// Live Tarpit telemetry snapshot for Ratatui HUD and reporting.
#[derive(Debug, Clone, Default)]
pub struct TarpitMetrics {
    pub active_sockets: usize,
    pub json_sinks_active: usize,
    pub html_sinks_active: usize,
    pub drained_cpu_seconds: u64,
    pub bytes_drained: u64,
    pub max_concurrency: usize,
}

impl TarpitMetrics {
    pub fn current() -> Self {
        Self {
            active_sockets: GLOBAL_TARPIT_ACTIVE_SOCKETS.load(Ordering::Relaxed),
            json_sinks_active: GLOBAL_JSON_SINKS_ACTIVE.load(Ordering::Relaxed),
            html_sinks_active: GLOBAL_HTML_SINKS_ACTIVE.load(Ordering::Relaxed),
            drained_cpu_seconds: GLOBAL_TARPIT_SECONDS_DRAINED.load(Ordering::Relaxed),
            bytes_drained: GLOBAL_TARPIT_BYTES_DRAINED.load(Ordering::Relaxed),
            max_concurrency: 512,
        }
    }
}

/// Asymmetric adversarial payload sink modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarpitPayloadMode {
    /// Infinite unclosed nested JSON array designed to force Out-Of-Memory (OOM)
    /// in client JSON parsers (Python requests/json.loads, Go json.Unmarshal, Node axios).
    InfiniteJsonSink,
    /// Infinite unclosed DOM tree designed to exhaust memory in headless browsers
    /// (Puppeteer, Playwright, Chromium, BeautifulSoup).
    InfiniteHtmlSink,
    /// Raw uncompressed entropy stream.
    RawChaff,
}

impl TarpitPayloadMode {
    /// Intelligently detects the most lethal sink format based on target path and client Accept header.
    pub fn detect(path: &str, accept: Option<&str>) -> Self {
        let p_lower = path.to_lowercase();
        let a_lower = accept.unwrap_or("").to_lowercase();

        if a_lower.contains("application/json")
            || p_lower.contains("/api")
            || p_lower.contains(".json")
        {
            Self::InfiniteJsonSink
        } else if a_lower.contains("text/html")
            || p_lower.contains(".php")
            || p_lower.contains(".html")
            || p_lower.contains("/admin")
            || p_lower.contains("/wp-")
        {
            Self::InfiniteHtmlSink
        } else {
            // Default to JSON sink: devastating against autonomous agent/Python scanners
            Self::InfiniteJsonSink
        }
    }

    pub fn content_type(&self) -> &'static str {
        match self {
            Self::InfiniteJsonSink => "application/json; charset=utf-8",
            Self::InfiniteHtmlSink => "text/html; charset=utf-8",
            Self::RawChaff => "application/octet-stream",
        }
    }
}

/// RAII Drop Guard tracking active tarpit sockets and recording adversarial seconds wasted.
pub struct TarpitGuard {
    counter: Arc<AtomicUsize>,
    mode: TarpitPayloadMode,
    start_time: Instant,
    bytes_served: Arc<AtomicU64>,
}

impl Drop for TarpitGuard {
    fn drop(&mut self) {
        let remaining = self
            .counter
            .fetch_sub(1, Ordering::SeqCst)
            .saturating_sub(1);
        GLOBAL_TARPIT_ACTIVE_SOCKETS.fetch_sub(1, Ordering::SeqCst);
        match self.mode {
            TarpitPayloadMode::InfiniteJsonSink => {
                GLOBAL_JSON_SINKS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
            }
            TarpitPayloadMode::InfiniteHtmlSink => {
                GLOBAL_HTML_SINKS_ACTIVE.fetch_sub(1, Ordering::Relaxed);
            }
            _ => {}
        }

        let elapsed_secs = self.start_time.elapsed().as_secs();
        let bytes = self.bytes_served.load(Ordering::Relaxed);

        GLOBAL_TARPIT_SECONDS_DRAINED.fetch_add(elapsed_secs, Ordering::Relaxed);
        GLOBAL_TARPIT_BYTES_DRAINED.fetch_add(bytes, Ordering::Relaxed);

        tracing::info!(
            "Adversary tarpit session terminated. Duration: {}s trapped, {} bytes drained. Remaining active tarpits: {}",
            elapsed_secs,
            bytes,
            remaining
        );
    }
}

/// Asymmetric Deep Tarpit streaming body implementing active resource drainage.
pub struct SlowDripBody {
    interval: Interval,
    mode: TarpitPayloadMode,
    step: usize,
    max_steps: usize,
    bytes_served: Arc<AtomicU64>,
    _guard: TarpitGuard,
}

impl SlowDripBody {
    pub fn new(
        interval_duration: Duration,
        max_steps: usize,
        mode: TarpitPayloadMode,
        counter: Arc<AtomicUsize>,
    ) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        GLOBAL_TARPIT_ACTIVE_SOCKETS.fetch_add(1, Ordering::SeqCst);
        match mode {
            TarpitPayloadMode::InfiniteJsonSink => {
                GLOBAL_JSON_SINKS_ACTIVE.fetch_add(1, Ordering::Relaxed);
            }
            TarpitPayloadMode::InfiniteHtmlSink => {
                GLOBAL_HTML_SINKS_ACTIVE.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }

        let bytes_served = Arc::new(AtomicU64::new(0));
        let guard = TarpitGuard {
            counter,
            mode,
            start_time: Instant::now(),
            bytes_served: Arc::clone(&bytes_served),
        };

        let mut ticker = interval(interval_duration);
        ticker.reset();

        Self {
            interval: ticker,
            mode,
            step: 0,
            max_steps,
            bytes_served,
            _guard: guard,
        }
    }

    /// Generates next chunk of adversarial payload without storing huge buffers in server memory.
    fn generate_drip_chunk(&self, step: usize) -> Bytes {
        match self.mode {
            TarpitPayloadMode::InfiniteJsonSink => {
                if step == 0 {
                    Bytes::from_static(b"{\"status\":\"active_sync\",\"protocol\":\"jfp-deep-tarpit\",\"stream\":[\n")
                } else {
                    let chunk = format!(
                        "  {{\"node_id\":{},\"sub_layer\":{{\"metric\":\"in_progress\",\"depth\":{},\"data\":[\n",
                        step, step
                    );
                    Bytes::from(chunk)
                }
            }
            TarpitPayloadMode::InfiniteHtmlSink => {
                if step == 0 {
                    Bytes::from_static(b"<!DOCTYPE html><html><head><title>Admin Dashboard</title></head><body><div id='log-stream'><table>\n")
                } else {
                    let chunk = format!(
                        "  <tr class='item-{}'><td><span>Analyzing system buffer block #{}...</span></td></tr>\n",
                        step, step
                    );
                    Bytes::from(chunk)
                }
            }
            TarpitPayloadMode::RawChaff => {
                let pseudo_random = (step.wrapping_mul(1103515245).wrapping_add(12345)) as u8;
                Bytes::copy_from_slice(&[pseudo_random])
            }
        }
    }
}

impl Body for SlowDripBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.step >= self.max_steps {
            return Poll::Ready(None);
        }

        match self.interval.poll_tick(cx) {
            Poll::Ready(_) => {
                let current_step = self.step;
                self.step += 1;
                let chunk = self.generate_drip_chunk(current_step);
                self.bytes_served
                    .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                Poll::Ready(Some(Ok(Frame::data(chunk))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.step >= self.max_steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tarpit_guard_lifecycle() {
        let counter = Arc::new(AtomicUsize::new(0));

        {
            let _body = SlowDripBody::new(
                Duration::from_millis(50),
                10,
                TarpitPayloadMode::InfiniteJsonSink,
                Arc::clone(&counter),
            );
            assert_eq!(counter.load(Ordering::SeqCst), 1);
        }

        // Dropping body must immediately decrement descriptor count
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_tarpit_mode_detection() {
        let json_mode = TarpitPayloadMode::detect("/api/v1/users", None);
        assert_eq!(json_mode, TarpitPayloadMode::InfiniteJsonSink);

        let html_mode = TarpitPayloadMode::detect("/index.php", Some("text/html"));
        assert_eq!(html_mode, TarpitPayloadMode::InfiniteHtmlSink);
    }

    #[tokio::test]
    async fn test_infinite_json_sink_generation() {
        let counter = Arc::new(AtomicUsize::new(0));
        let body = SlowDripBody::new(
            Duration::from_millis(100),
            100,
            TarpitPayloadMode::InfiniteJsonSink,
            counter,
        );

        let chunk0 = body.generate_drip_chunk(0);
        assert!(chunk0.starts_with(b"{\"status\""));

        let chunk1 = body.generate_drip_chunk(1);
        assert!(chunk1.starts_with(b"  {\"node_id\":1"));
    }
}
