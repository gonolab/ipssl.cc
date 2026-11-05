//! Response rate limiting (RRL) for UDP.
//!
//! UDP source addresses can be forged, so an attacker can make the server
//! send answers to a victim. Each client network (IPv4 /24, IPv6 /56 by
//! default) gets a token bucket: `responses_per_second` tokens a second, up
//! to `burst`. Once it runs dry, every `slip`-th response goes out truncated
//! (TC=1, no records), which tells real resolvers to retry over TCP, where
//! the source cannot be forged and nothing is limited. The rest are dropped.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Result, ensure};
use ipnet::IpNet;

use crate::config::RateLimitConfig;

/// Number of independently locked parts of the table, to keep lock
/// contention low on multi-core servers.
const SHARDS: usize = 32;

/// Shortest time between two sweeps of idle entries in one shard. Bounds
/// the cost of sweeping when the table is full of busy networks.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// What to do with a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Send it as usual.
    Allow,
    /// Send a truncated response instead, so the client retries over TCP.
    Slip,
    /// Send nothing.
    Drop,
}

pub struct RateLimiter {
    /// Tokens added per second.
    rate: f64,
    /// Bucket size.
    burst: f64,
    /// Time for an empty bucket to fill up; after that an entry carries no
    /// state a fresh one would not have, so it can be forgotten.
    refill: Duration,
    slip: u32,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
    exempt: Vec<IpNet>,
    /// Random per process, so nobody can aim many networks at one shard.
    hasher: RandomState,
    shards: Box<[Mutex<Shard>]>,
    shard_capacity: usize,
    /// Shared by all networks that arrive while the table is full, so
    /// flooding it with forged sources does not get anyone past the limit.
    overflow: Mutex<Bucket>,
}

struct Shard {
    buckets: HashMap<IpAddr, Bucket>,
    last_sweep: Instant,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
    /// Responses limited so far; drives the slip pattern.
    limited: u32,
}

impl RateLimiter {
    /// Builds a limiter from the config, or `None` when limiting is off
    /// (`responses_per_second = 0`).
    pub fn from_config(cfg: &RateLimitConfig) -> Result<Option<Self>> {
        if cfg.responses_per_second == 0 {
            return Ok(None);
        }
        ensure!(cfg.burst >= 1, "rate_limit.burst must be at least 1");
        ensure!(
            cfg.ipv4_prefix <= 32,
            "rate_limit.ipv4_prefix must be 0..=32"
        );
        ensure!(
            cfg.ipv6_prefix <= 128,
            "rate_limit.ipv6_prefix must be 0..=128"
        );
        ensure!(
            cfg.max_tracked >= 1,
            "rate_limit.max_tracked must be at least 1"
        );

        let now = Instant::now();
        let rate = f64::from(cfg.responses_per_second);
        let burst = f64::from(cfg.burst);
        let shards = SHARDS.min(cfg.max_tracked);
        Ok(Some(Self {
            rate,
            burst,
            refill: Duration::from_secs_f64(burst / rate),
            slip: cfg.slip,
            ipv4_prefix: cfg.ipv4_prefix,
            ipv6_prefix: cfg.ipv6_prefix,
            exempt: cfg.exempt.clone(),
            hasher: RandomState::new(),
            shards: (0..shards)
                .map(|_| {
                    Mutex::new(Shard {
                        buckets: HashMap::new(),
                        last_sweep: now,
                    })
                })
                .collect(),
            shard_capacity: cfg.max_tracked / shards,
            overflow: Mutex::new(Bucket::full(burst, now)),
        }))
    }

    /// Accounts for one response to `client` and says what to do with it.
    pub fn check(&self, client: IpAddr) -> Verdict {
        self.check_at(client, Instant::now())
    }

    /// Number of client networks currently tracked.
    pub fn tracked(&self) -> usize {
        self.shards.iter().map(|s| lock(s).buckets.len()).sum()
    }

    fn check_at(&self, client: IpAddr, now: Instant) -> Verdict {
        let client = client.to_canonical();
        if self.exempt.iter().any(|net| net.contains(&client)) {
            return Verdict::Allow;
        }

        let network = self.network(client);
        let index = self.hasher.hash_one(network) as usize % self.shards.len();
        let mut shard = lock(&self.shards[index]);
        if let Some(bucket) = shard.buckets.get_mut(&network) {
            return self.take(bucket, now);
        }

        // A network we are not tracking yet. Forget idle ones first:
        // their buckets are full, the same as a new entry's.
        if now.saturating_duration_since(shard.last_sweep) >= SWEEP_INTERVAL {
            let refill = self.refill;
            shard
                .buckets
                .retain(|_, b| now.saturating_duration_since(b.updated) < refill);
            shard.last_sweep = now;
        }
        if shard.buckets.len() < self.shard_capacity {
            let mut bucket = Bucket::full(self.burst, now);
            let verdict = self.take(&mut bucket, now);
            shard.buckets.insert(network, bucket);
            return verdict;
        }
        drop(shard);

        self.take(&mut lock(&self.overflow), now)
    }

    /// The client's network address, used as the bucket key.
    fn network(&self, client: IpAddr) -> IpAddr {
        match client {
            IpAddr::V4(ip) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.ipv4_prefix));
                IpAddr::V4(Ipv4Addr::from(u32::from(ip) & mask.unwrap_or(0)))
            }
            IpAddr::V6(ip) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.ipv6_prefix));
                IpAddr::V6(Ipv6Addr::from(u128::from(ip) & mask.unwrap_or(0)))
            }
        }
    }

    fn take(&self, bucket: &mut Bucket, now: Instant) -> Verdict {
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.updated = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Verdict::Allow;
        }
        bucket.limited = bucket.limited.wrapping_add(1);
        if self.slip > 0 && bucket.limited.is_multiple_of(self.slip) {
            Verdict::Slip
        } else {
            Verdict::Drop
        }
    }
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            updated: now,
            limited: 0,
        }
    }
}

/// Locks `mutex`, carrying on if another thread panicked while holding it:
/// a bucket left half-updated is harmless.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(cfg: RateLimitConfig) -> RateLimiter {
        RateLimiter::from_config(&cfg).unwrap().unwrap()
    }

    fn cfg(responses_per_second: u32, burst: u32, slip: u32) -> RateLimitConfig {
        RateLimitConfig {
            responses_per_second,
            burst,
            slip,
            ..RateLimitConfig::default()
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn disabled_when_rate_is_zero() {
        assert!(RateLimiter::from_config(&cfg(0, 10, 2)).unwrap().is_none());
    }

    #[test]
    fn rejects_bad_settings() {
        assert!(RateLimiter::from_config(&cfg(10, 0, 2)).is_err());
        let v4 = RateLimitConfig {
            ipv4_prefix: 33,
            ..RateLimitConfig::default()
        };
        assert!(RateLimiter::from_config(&v4).is_err());
    }

    #[test]
    fn burst_then_slip_pattern() {
        let rl = limiter(cfg(1, 3, 2));
        let now = Instant::now();
        let client = ip("192.0.2.1");
        let verdicts: Vec<_> = (0..7).map(|_| rl.check_at(client, now)).collect();
        use Verdict::*;
        assert_eq!(verdicts, [Allow, Allow, Allow, Drop, Slip, Drop, Slip]);
    }

    #[test]
    fn slip_zero_drops_everything() {
        let rl = limiter(cfg(1, 1, 0));
        let now = Instant::now();
        let client = ip("192.0.2.1");
        assert_eq!(rl.check_at(client, now), Verdict::Allow);
        for _ in 0..5 {
            assert_eq!(rl.check_at(client, now), Verdict::Drop);
        }
    }

    #[test]
    fn refills_over_time() {
        let rl = limiter(cfg(10, 1, 0));
        let start = Instant::now();
        let client = ip("192.0.2.1");
        assert_eq!(rl.check_at(client, start), Verdict::Allow);
        assert_eq!(rl.check_at(client, start), Verdict::Drop);
        // 10 per second: one token after 100 ms.
        let later = start + Duration::from_millis(100);
        assert_eq!(rl.check_at(client, later), Verdict::Allow);
        assert_eq!(rl.check_at(client, later), Verdict::Drop);
    }

    #[test]
    fn groups_clients_by_network() {
        let rl = limiter(cfg(1, 1, 0));
        let now = Instant::now();
        assert_eq!(rl.check_at(ip("192.0.2.1"), now), Verdict::Allow);
        // Same /24.
        assert_eq!(rl.check_at(ip("192.0.2.200"), now), Verdict::Drop);
        // IPv4-mapped IPv6 counts as the same IPv4 network.
        assert_eq!(rl.check_at(ip("::ffff:192.0.2.9"), now), Verdict::Drop);
        // Another /24.
        assert_eq!(rl.check_at(ip("192.0.3.1"), now), Verdict::Allow);

        assert_eq!(rl.check_at(ip("2001:db8:0:1::1"), now), Verdict::Allow);
        // Same /56.
        assert_eq!(rl.check_at(ip("2001:db8:0:ff::2"), now), Verdict::Drop);
        // Another /56.
        assert_eq!(rl.check_at(ip("2001:db8:0:100::1"), now), Verdict::Allow);
        assert_eq!(rl.tracked(), 4);
    }

    #[test]
    fn exempt_networks_are_never_limited() {
        let rl = limiter(RateLimitConfig {
            exempt: vec!["192.0.2.0/24".parse().unwrap()],
            ..cfg(1, 1, 0)
        });
        let now = Instant::now();
        for _ in 0..10 {
            assert_eq!(rl.check_at(ip("192.0.2.1"), now), Verdict::Allow);
        }
        assert_eq!(rl.tracked(), 0);
    }

    #[test]
    fn full_table_shares_one_bucket() {
        let rl = limiter(RateLimitConfig {
            max_tracked: SHARDS,
            ..cfg(1, 1, 0)
        });
        let now = Instant::now();
        let allowed = (0..=255u8)
            .flat_map(|a| (0..4u8).map(move |b| IpAddr::V4(Ipv4Addr::new(10, a, b, 1))))
            .filter(|client| rl.check_at(*client, now) == Verdict::Allow)
            .count();
        // Every tracked network got its one token; all the others shared one.
        let tracked = rl.tracked();
        assert!(tracked <= SHARDS);
        assert_eq!(allowed, tracked + 1);
    }

    #[test]
    fn idle_networks_are_forgotten() {
        let rl = limiter(RateLimitConfig {
            max_tracked: 1,
            ..cfg(1, 1, 0)
        });
        let start = Instant::now();
        assert_eq!(rl.check_at(ip("192.0.2.1"), start), Verdict::Allow);
        // The table is full, so a second network uses the overflow bucket.
        assert_eq!(rl.check_at(ip("198.51.100.1"), start), Verdict::Allow);
        assert_eq!(rl.check_at(ip("203.0.113.1"), start), Verdict::Drop);

        // Once the first network has been idle long enough, it is swept
        // out and the next new network gets its own entry again.
        let later = start + Duration::from_secs(2);
        assert_eq!(rl.check_at(ip("203.0.113.1"), later), Verdict::Allow);
        assert_eq!(rl.tracked(), 1);
        assert_eq!(rl.check_at(ip("203.0.113.1"), later), Verdict::Drop);
    }
}
