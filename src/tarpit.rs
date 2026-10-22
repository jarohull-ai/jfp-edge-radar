use bytes::Bytes;
use hyper::body::{Body, Frame};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{interval, Interval};

/// Infinite Slow-Drip streaming body designed to exhaust attacker HTTP client concurrency
/// and trap autonomous AI agents in endless inference polling.
pub struct SlowDripBody {
    interval: Interval,
    remaining_bytes: usize,
    drip_byte: Bytes,
}

impl SlowDripBody {
    pub fn new(interval_duration: Duration, total_bytes: usize) -> Self {
        let mut ticker = interval(interval_duration);
        // Consume first tick immediately so the initial byte goes out to confirm connection
        ticker.reset();

        Self {
            interval: ticker,
            remaining_bytes: total_bytes,
            drip_byte: Bytes::from_static(b"."),
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
