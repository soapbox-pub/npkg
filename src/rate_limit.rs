//! Token buckets, after npanel's.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use tokio::time::Instant;

/// How many tokens a key gets, and how long a spent bucket takes to refill.
#[derive(Clone, Copy, Debug)]
pub struct RateLimit {
    /// Tokens a key starts with, and the most it can bank.
    pub capacity: f64,
    /// How long an empty bucket takes to refill completely.
    pub refill: Duration,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

/// A token bucket per key, with a bounded number of keys.
///
/// Keys come from outside, so the map is capped. A bucket that has refilled
/// is the same as one that never existed, so those go first; past that, the
/// least recently used.
pub struct RateLimiter<K> {
    limit: RateLimit,
    buckets: HashMap<K, Bucket>,
    max_keys: usize,
}

impl<K: Eq + Hash + Clone> RateLimiter<K> {
    pub fn new(limit: RateLimit, max_keys: usize) -> Self {
        RateLimiter { limit, buckets: HashMap::new(), max_keys }
    }

    /// Whether `key` has a token left, without spending it.
    pub fn check(&mut self, key: &K) -> bool {
        let now = Instant::now();
        self.buckets.get(key).is_none_or(|bucket| self.refilled(bucket, now) >= 1.0)
    }

    /// Spend one token for `key`, or return false when its bucket is empty.
    pub fn take(&mut self, key: &K) -> bool {
        let now = Instant::now();
        if !self.buckets.contains_key(key) {
            self.evict(now);
            self.buckets.insert(key.clone(), Bucket { tokens: self.limit.capacity, updated: now });
        }
        let limit = self.limit;
        let Some(bucket) = self.buckets.get_mut(key) else { return false };
        let tokens = refill(bucket, limit, now);
        bucket.updated = now;
        if tokens < 1.0 {
            bucket.tokens = tokens;
            return false;
        }
        bucket.tokens = tokens - 1.0;
        true
    }

    fn refilled(&self, bucket: &Bucket, now: Instant) -> f64 {
        refill(bucket, self.limit, now)
    }

    fn evict(&mut self, now: Instant) {
        if self.buckets.len() < self.max_keys {
            return;
        }
        let limit = self.limit;
        self.buckets.retain(|_, bucket| refill(bucket, limit, now) < limit.capacity);
        while self.buckets.len() >= self.max_keys {
            let Some(oldest) = self.buckets.iter().min_by_key(|(_, bucket)| bucket.updated).map(|(key, _)| key.clone()) else { break };
            self.buckets.remove(&oldest);
        }
    }
}

/// A bucket's tokens brought up to date, capped at capacity.
fn refill(bucket: &Bucket, limit: RateLimit, now: Instant) -> f64 {
    let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
    (bucket.tokens + elapsed / limit.refill.as_secs_f64() * limit.capacity).min(limit.capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: RateLimit = RateLimit { capacity: 2.0, refill: Duration::from_secs(10) };

    #[tokio::test(start_paused = true)]
    async fn spends_and_refills() {
        let mut limiter = RateLimiter::new(LIMIT, 10);
        assert!(limiter.take(&"a"));
        assert!(limiter.check(&"a"));
        assert!(limiter.take(&"a"));
        assert!(!limiter.check(&"a"));
        assert!(!limiter.take(&"a"));
        assert!(limiter.take(&"b"));

        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(limiter.take(&"a"));
        assert!(!limiter.take(&"a"));
    }

    #[tokio::test(start_paused = true)]
    async fn caps_keys() {
        let mut limiter = RateLimiter::new(LIMIT, 2);
        for key in ["a", "b", "c"] {
            limiter.take(&key);
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        assert_eq!(limiter.buckets.len(), 2);
        // The least recently used went.
        assert!(!limiter.buckets.contains_key("a"));
    }
}
