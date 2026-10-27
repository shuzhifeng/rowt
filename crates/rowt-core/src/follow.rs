//! `auto`'s failover follower — the decision half of `watch follow`.
//!
//! sing-box's urltest leaves a server only when a ROUND re-picks. A connection
//! through the pick that fails deletes the pick's figure (its one stored delay)
//! and is logged, and the group keeps dialing the dead pick until the next
//! round — up to a whole interval later (1.13: `protocol/group/urltest.go`,
//! `DialContext` then `urlTest`). The follower asks the clash API every few
//! seconds whether the pick still has a figure, and when it has none asks the
//! group to re-test at once (`GET /group/auto/delay`), which tests only the
//! servers without a fresh figure and moves to a live one.
//!
//! What is decided here is WHEN to ask: at once on a lost figure, then — while
//! the re-tests keep finding nothing live — at a doubling interval (twice the
//! check period, then twice that, up to [`MAX_WAIT_SECS`]), so an outage of
//! every server costs a re-test every ten minutes, not every fifteen seconds.
//! A pick with a figure resets it. The shell's `_watch_follow` is the same
//! loop, step for step.

/// The longest a follower waits between two fruitless re-tests.
pub const MAX_WAIT_SECS: u64 = 600;

/// What one look at the pick found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Look {
    /// The pick has a figure: it answered its last test or connection.
    Fresh,
    /// The pick has none: sing-box saw it fail, or has not tested it yet.
    Lost,
    /// No pick, or the clash API did not answer: nothing to decide on.
    Unknown,
}

/// Read the clash API's `GET /proxies/<tag>` body: a `history` array with an
/// entry is a figure, an empty one is none, anything else is no answer.
pub fn look(body: &str) -> Look {
    let v: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return Look::Unknown,
    };
    match v.get("history").and_then(|h| h.as_array()) {
        Some(a) if !a.is_empty() => Look::Fresh,
        Some(_) => Look::Lost,
        None => Look::Unknown,
    }
}

/// The follower's memory between looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Follow {
    /// Seconds to hold off after the next fruitless re-test.
    pub wait: u64,
    /// Epoch before which no re-test is asked for (0 = any time).
    pub next: u64,
}

impl Follow {
    pub fn new(every: u64) -> Follow {
        Follow { wait: every * 2, next: 0 }
    }

    /// Should this look ask for a re-test? A fresh pick resets the backoff.
    pub fn should_retest(&mut self, look: Look, now: u64, every: u64) -> bool {
        match look {
            Look::Fresh => {
                *self = Follow::new(every);
                false
            }
            Look::Lost => now >= self.next,
            Look::Unknown => false,
        }
    }

    /// After a re-test: a live pick resets the backoff; none holds off for
    /// `wait` seconds and doubles it, up to [`MAX_WAIT_SECS`].
    pub fn after_retest(&mut self, live: bool, now: u64, every: u64) {
        if live {
            *self = Follow::new(every);
        } else {
            self.next = now + self.wait;
            self.wait = (self.wait * 2).min(MAX_WAIT_SECS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_history_array_is_the_figure() {
        assert_eq!(look(r#"{"history":[{"time":"x","delay":80}],"name":"a"}"#), Look::Fresh);
        assert_eq!(look(r#"{"history":[],"name":"a"}"#), Look::Lost);
        assert_eq!(look(r#"{"name":"a"}"#), Look::Unknown);
        assert_eq!(look(""), Look::Unknown);
        assert_eq!(look("not json"), Look::Unknown);
    }

    /// A lost figure is acted on at the very next look — the whole point: the
    /// switch lands within one check period plus the re-test, well inside a
    /// minute at the default 15 s, instead of a round away.
    #[test]
    fn a_lost_figure_is_retested_at_once() {
        let mut f = Follow::new(15);
        assert!(!f.should_retest(Look::Fresh, 100, 15));
        assert!(f.should_retest(Look::Lost, 115, 15));
        f.after_retest(true, 116, 15);
        assert_eq!(f, Follow::new(15));
    }

    #[test]
    fn fruitless_retests_back_off_doubling_up_to_ten_minutes() {
        let mut f = Follow::new(15);
        let mut now = 1000;
        let mut gaps = Vec::new();
        for _ in 0..8 {
            assert!(f.should_retest(Look::Lost, now, 15));
            f.after_retest(false, now, 15);
            gaps.push(f.next - now);
            // Every look before `next` stays quiet.
            assert!(!f.should_retest(Look::Lost, f.next - 1, 15));
            now = f.next;
        }
        assert_eq!(gaps, [30, 60, 120, 240, 480, 600, 600, 600]);
    }

    #[test]
    fn a_fresh_figure_or_no_answer_never_asks_and_fresh_resets() {
        let mut f = Follow::new(15);
        f.after_retest(false, 0, 15);
        f.after_retest(false, 30, 15);
        assert!(!f.should_retest(Look::Unknown, 10_000, 15));
        assert!(!f.should_retest(Look::Fresh, 10_000, 15));
        assert_eq!(f, Follow::new(15));
    }
}
