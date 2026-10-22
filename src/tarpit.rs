use bytes::Bytes;
use hyper::body::{Body, Frame};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{interval, Interval};

/// RAII Drop Guard to automatically decrement active tarpit descriptor count on disconnect.
pub struct TarpitGuard {
    counter: Arc<AtomicUsize>,
}

impl Drop for TarpitGuard {
    fn drop(&mut self) {
        let remaining = self.counter.fetch_sub(1, Ordering::SeqCst).saturating_sub(1);
        tracing::debug!("Tarpit session ended. Active tarpit descriptors: {}", remaining);
    }
}

/// Infinite Slow-Drip streaming body with active descriptor limitation.
pub struct SlowDripBody {
    interval: Interval,
    remaining_bytes: usize,
    drip_byte: Bytes,
    _guard: TarpitGuard,
}

impl SlowDripBody {
    pub fn new(
        interval_duration: Duration,
        total_bytes: usize,
        counter: Arc<AtomicUsize>,
    ) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        let guard = TarpitGuard { counter };

        let mut ticker = interval(interval_duration);
        ticker.reset();

        Self {
            interval: ticker,
            remaining_bytes: total_bytes,
            drip_byte: Bytes::from_static(b"."),
            _guard: guard,
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
        if self.remaining_bytes == 0 {
            return Poll::Ready(None);
        }

        match self.interval.poll_tick(cx) {
            Poll::Ready(_) => {
                self.remaining_bytes -= 1;
                Poll::Ready(Some(Ok(Frame::data(self.drip_byte.clone()))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.remaining_bytes == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tarpit_guard_lifecycle() {
        let counter = Arc::new(AtomicUsize::new(0));

        {
            let _body = SlowDripBody::new(Duration::from_millis(50), 10, Arc::clone(&counter));
            assert_eq!(counter.load(Ordering::SeqCst), 1);
        }

        // Dropping body must immediately decrement descriptor count
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }
}
