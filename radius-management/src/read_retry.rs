//! Retry a complete read-only capture after transient publication contention.
use std::{
    io,
    time::{Duration, Instant},
};

const BUDGET: Duration = Duration::from_millis(250);

pub(crate) fn snapshot<T>(capture: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let started = Instant::now();
    retry(capture, || started.elapsed(), std::thread::sleep)
}

fn retry<T>(
    mut capture: impl FnMut() -> io::Result<T>,
    elapsed: impl Fn() -> Duration,
    mut pause: impl FnMut(Duration),
) -> io::Result<T> {
    let mut delay = Duration::from_millis(2);
    loop {
        match capture() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let remaining = BUDGET.saturating_sub(elapsed());
                if delay >= remaining {
                    return Err(error);
                }
                // The failed attempt must have dropped its entire snapshot.
                // This helper must never wrap a mutation or a partial read.
                pause(delay);
                if elapsed() >= BUDGET {
                    return Err(error);
                }
                delay = (delay * 2).min(Duration::from_millis(32));
            }
            result => return result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn publication_contention_can_outlast_the_previous_six_millisecond_window() {
        let clock = Cell::new(Duration::ZERO);
        let calls = Cell::new(0);
        let result = retry(
            || {
                calls.set(calls.get() + 1);
                if clock.get() < Duration::from_millis(40) {
                    Err(io::ErrorKind::WouldBlock.into())
                } else {
                    Ok("complete fresh view")
                }
            },
            || clock.get(),
            |delay| clock.set(clock.get() + delay),
        );
        assert_eq!(result.unwrap(), "complete fresh view");
        assert!(calls.get() > 4);
        assert!(clock.get() < BUDGET);
    }

    #[test]
    fn persistent_contention_stops_within_its_budget() {
        let clock = Cell::new(Duration::ZERO);
        let calls = Cell::new(0);
        let result: io::Result<()> = retry(
            || {
                calls.set(calls.get() + 1);
                clock.set(clock.get() + Duration::from_millis(1));
                Err(io::ErrorKind::WouldBlock.into())
            },
            || clock.get(),
            |delay| clock.set(clock.get() + delay),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(calls.get() > 1 && calls.get() < 20);
        assert!(clock.get() <= BUDGET);
    }

    #[test]
    fn non_contention_failures_are_not_retried() {
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::NotFound,
            io::ErrorKind::InvalidData,
        ] {
            let calls = Cell::new(0);
            let result: io::Result<()> = retry(
                || {
                    calls.set(calls.get() + 1);
                    Err(kind.into())
                },
                || Duration::ZERO,
                |_| panic!("must not retry a different failure"),
            );
            assert_eq!(result.unwrap_err().kind(), kind);
            assert_eq!(calls.get(), 1);
        }
    }

    #[test]
    fn slow_failed_capture_does_not_start_another_attempt_after_the_budget() {
        let result: io::Result<()> = retry(
            || Err(io::ErrorKind::WouldBlock.into()),
            || BUDGET + Duration::from_millis(1),
            |_| panic!("retry budget has already elapsed"),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn successful_capture_needs_no_retry() {
        assert_eq!(snapshot(|| Ok(42)).unwrap(), 42);
    }

    #[test]
    fn delayed_wakeup_does_not_start_another_capture() {
        let clock = Cell::new(Duration::ZERO);
        let calls = Cell::new(0);
        let result: io::Result<()> = retry(
            || {
                calls.set(calls.get() + 1);
                Err(io::ErrorKind::WouldBlock.into())
            },
            || clock.get(),
            |_| clock.set(BUDGET + Duration::from_millis(1)),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(calls.get(), 1);
    }
}
