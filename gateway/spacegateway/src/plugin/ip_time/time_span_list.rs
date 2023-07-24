use std::{
    collections::BTreeSet,
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
};

use ipnet::IpNet;
use tardis::chrono::{Local, NaiveTime};

use super::IpTimeRule;

/// write once and read many times
pub struct TimeSpanList<T> {
    spans: Vec<TimeSpan<T>>,
    /// hint for last query
    latest_hint: AtomicUsize,
}

impl<T> TimeSpanList<T> {
    /// it should be almost O(1)
    pub fn query(&self) -> &T {
        let time = Local::now().time();
        // it should be very relax hear since lastest is just a hint
        let mut idx = self.latest_hint.load(Ordering::Relaxed);
        // find next
        let len = self.spans.len();
        loop {
            let next = (idx + 1) % len;
            if self.spans[next].start < time {
                idx = next
            } else {
                self.latest_hint.store(idx, Ordering::Relaxed);
                break &self.spans[idx].data;
            }
        }
    }
}
#[derive(Debug)]
pub struct TimeSpan<T> {
    pub start: NaiveTime,
    pub data: T,
}

impl<T> PartialEq for TimeSpan<T> {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start
    }
}

impl<T> Eq for TimeSpan<T> {}

impl<T> Ord for TimeSpan<T> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.start.cmp(&other.start)
    }
}

impl<T> PartialOrd for TimeSpan<T> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.start.partial_cmp(&other.start)
    }
}

impl TimeSpanList<BTreeSet<IpNet>> {
    pub fn add_rules(&mut self, ipnets: impl IntoIterator<Item = IpNet>, time_range: Range<NaiveTime>) {
        if time_range.start < time_range.end {
            match self.spans.binary_search_by(|span| span.start.cmp(&time_range.start)) {
                Ok(idx) => {
                    let idx_end = self.spans.binary_search_by(|span| span.start.cmp(&time_range.end)).unwrap_or_else(|idx| {
                        self.spans.insert(
                            idx,
                            TimeSpan {
                                start: time_range.end,
                                data: BTreeSet::new(),
                            },
                        );
                        idx
                    });
                    for ipnet in ipnets {
                        for spans in &mut self.spans[idx..idx_end] {
                            spans.data.insert(ipnet);
                        }
                    }
                }
                Err(idx) => {}
            }
        }
    }
}
