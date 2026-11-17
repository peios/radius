//! Principal budgets. Interval union and sum are independent quota dimensions.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use time::{Date, Month, OffsetDateTime};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Dimension {
    InputBytes,
    OutputBytes,
    TotalBytes,
    TotalSessionTime,
    ConnectedTime,
    Concurrent,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Period {
    Lifetime,
    Day,
    Week,
    Month,
}
impl Period {
    /// UTC calendar periods. Original event times, not arrival times, select a
    /// bucket; caller must surface uncertain counter-boundary attribution.
    pub fn bounds(self, now_ms: i64) -> Result<(i64, i64)> {
        if now_ms < 0 {
            return Err(Error::Malformed);
        }
        let dt =
            OffsetDateTime::from_unix_timestamp(now_ms / 1000).map_err(|_| Error::Malformed)?;
        let date = dt.date();
        let day = (now_ms / 86_400_000) * 86_400_000;
        Ok(match self {
            Self::Lifetime => (0, i64::MAX),
            Self::Day => (day, day.saturating_add(86_400_000)),
            Self::Week => {
                let from = day.saturating_sub(
                    i64::from(date.weekday().number_days_from_monday()) * 86_400_000,
                );
                (from.max(0), from.saturating_add(7 * 86_400_000))
            }
            Self::Month => {
                let start = Date::from_calendar_date(date.year(), date.month(), 1)
                    .map_err(|_| Error::Malformed)?;
                let year = date.year() + i32::from(date.month() == Month::December);
                let end = Date::from_calendar_date(year, date.month().next(), 1)
                    .map_err(|_| Error::Malformed)?;
                (
                    start.midnight().assume_utc().unix_timestamp() * 1000,
                    end.midnight().assume_utc().unix_timestamp() * 1000,
                )
            }
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub id: String,
    pub principal: String,
    pub policy: Option<String>,
    pub dimension: Dimension,
    pub period: Period,
    /// Bytes, milliseconds, or sessions according to dimension.
    pub maximum: u64,
    pub disconnect: bool,
}
impl Budget {
    pub fn validate(&self) -> Result<()> {
        if self.id.is_empty()
            || self.id.len() > 128
            || self.principal.len() > 192
            || !valid_sid(&self.principal)
            || self
                .principal
                .bytes()
                .any(|b| !b.is_ascii_digit() && b != b'S' && b != b'-')
            || self
                .policy
                .as_ref()
                .is_some_and(|s| s.is_empty() || s.len() > 128)
            || (self.dimension == Dimension::Concurrent && self.period != Period::Lifetime)
        {
            return Err(Error::Configuration("invalid principal budget".into()));
        }
        Ok(())
    }
}
fn valid_sid(s: &str) -> bool {
    let parts: Vec<_> = s.split('-').collect();
    parts.len() >= 4
        && parts.len() <= 18
        && parts[0] == "S"
        && parts[1] == "1"
        && parts[2].parse::<u64>().is_ok_and(|n| n <= 0xffffffffffff)
        && parts[2..].iter().all(|p| {
            !p.is_empty()
                && (*p == "0" || !p.starts_with('0'))
                && p.bytes().all(|b| b.is_ascii_digit())
        })
        && parts[3..].iter().all(|p| p.parse::<u32>().is_ok())
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Balance {
    pub budget: Budget,
    pub used: u64,
    pub remaining: u64,
    pub uncertain: bool,
    pub period_start_ms: i64,
    pub period_end_ms: i64,
}
impl Balance {
    pub fn exhausted(&self) -> bool {
        self.used >= self.budget.maximum
    }
}

/// Return total session-milliseconds and connected-milliseconds after clipping
/// to one period. Adjacency is joined; invalid/reversed intervals add nothing.
pub fn interval_usage(
    intervals: impl IntoIterator<Item = (i64, i64)>,
    from: i64,
    until: i64,
) -> (u64, u64) {
    let mut ranges: Vec<_> = intervals
        .into_iter()
        .map(|(a, b)| (a.max(from), b.min(until)))
        .filter(|(a, b)| a < b)
        .collect();
    ranges.sort_unstable();
    let mut total = 0u64;
    let mut connected = 0u64;
    let mut union: Option<(i64, i64)> = None;
    for (start, end) in ranges {
        total = total.saturating_add(end.saturating_sub(start) as u64);
        match union {
            None => union = Some((start, end)),
            Some((a, b)) if start <= b => union = Some((a, b.max(end))),
            Some((a, b)) => {
                connected = connected.saturating_add(b.saturating_sub(a) as u64);
                union = Some((start, end));
            }
        }
    }
    if let Some((a, b)) = union {
        connected = connected.saturating_add(b.saturating_sub(a) as u64);
    }
    (total, connected)
}
