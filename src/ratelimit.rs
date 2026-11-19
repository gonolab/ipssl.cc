//! Response rate limiting (RRL) for UDP.
//!
//! UDP source addresses can be forged, so an attacker can make the server
//! send answers to a victim. Each client network (IPv4 /24, IPv6 /56 by
//! default) gets a token bucket: `responses_per_second` tokens a second, up
//! to `burst`. Once it runs dry, every `slip`-th response goes out truncated
//! (TC=1, no records), which tells real resolvers to retry over TCP, where
//! the source cannot be forged and nothing is limited. The rest are dropped.
//!
//! The table tracks at most `max_tracked` networks. A bucket that has filled
//! up again carries no state a new one would not have, so such entries are
//! forgotten: about once a second, and whenever a new network finds the
//! table full. New networks share one overflow bucket only while every
//! network in their part of the table is still active (checked at most
//! every 100 ms).

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::Result;
use ipnet::IpNet;

use crate::config::RateLimitConfig;

/// Most independently locked parts of the table, to keep lock contention
/// low on multi-core servers.
const SHARDS: usize = 32;

/// Smallest share of `max_tracked` per part. A new network can only take
/// the place of one in its own part, so small tables get fewer parts, each
/// big enough to hold an idle entry when any part does.
const NETWORKS_PER_SHARD: usize = 1024;

/// How often a part of the table forgets idle entries while there is room.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Shortest time between two sweeps of one part while the table is full.
/// A sweep reads every entry of the part, so this bounds the cost when
/// every tracked network is busy and there is nothing to forget; until
/// the next sweep, new networks there share the overflow bucket.
const FULL_SWEEP_INTERVAL: Duration = Duration::from_millis(100);

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
    slip: u32,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
    exempt: Vec<IpNet>,
    /// Random per process, so nobody can aim many networks at one shard.
    hasher: RandomState,
    shards: Box<[Mutex<Shard>]>,
    /// Networks tracked in all shards together, at most `max_tracked`.
    tracked: AtomicUsize,
    max_tracked: usize,
    /// Shared by all networks that arrive while the table is full of active
    /// ones, so flooding it with forged sources gets nobody past the limit.
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
        cfg.validate()?;
        if cfg.responses_per_second == 0 {
            return Ok(None);
        }

        let mut limiter = Self::new(
            f64::from(cfg.responses_per_second),
            cfg.burst,
            cfg.ipv4_prefix,
            cfg.ipv6_prefix,
            cfg.max_tracked,
        )
        .with_slip(cfg.slip);
        limiter.exempt = cfg.exempt.clone();
        Ok(Some(limiter))
    }

    /// A limiter allowing `rate` requests a second (fractions are fine, such
    /// as `1e-6` for a test that must never see a refill) and bursts of
    /// `burst` per client network. Limited requests are dropped until
    /// [`Self::with_slip`] says otherwise. Arguments must be in range (see
    /// [`RateLimitConfig::validate_networks`]).
    pub fn new(
        rate: f64,
        burst: u32,
        ipv4_prefix: u8,
        ipv6_prefix: u8,
        max_tracked: usize,
    ) -> Self {
        let now = Instant::now();
        let burst = f64::from(burst);
        let shards = (max_tracked / NETWORKS_PER_SHARD).clamp(1, SHARDS);
        Self {
            rate,
            burst,
            slip: 0,
            ipv4_prefix,
            ipv6_prefix,
            exempt: Vec::new(),
            hasher: RandomState::new(),
            shards: (0..shards)
                .map(|_| {
                    Mutex::new(Shard {
                        buckets: HashMap::new(),
                        last_sweep: now,
                    })
                })
                .collect(),
            tracked: AtomicUsize::new(0),
            max_tracked,
            overflow: Mutex::new(Bucket::full(burst, now)),
        }
    }

    /// Sends every `slip`-th limited response truncated instead of dropping
    /// it; 0 drops them all.
    pub fn with_slip(mut self, slip: u32) -> Self {
        self.slip = slip;
        self
    }

    /// Accounts for one response to `client` and says what to do with it.
    pub fn check(&self, client: IpAddr) -> Verdict {
        self.check_at(client, Instant::now())
    }

    /// Number of client networks currently tracked.
    pub fn tracked(&self) -> usize {
        self.tracked.load(Ordering::Relaxed)
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

        // A network we are not tracking yet. Forget idle ones now and then,
        // and whenever the table is full, so the new one can take the place
        // of one of them.
        if now.saturating_duration_since(shard.last_sweep) >= SWEEP_INTERVAL {
            self.sweep(&mut shard, now);
        }
        let mut reserved = self.reserve();
        if !reserved && now.saturating_duration_since(shard.last_sweep) >= FULL_SWEEP_INTERVAL {
            self.sweep(&mut shard, now);
            reserved = self.reserve();
        }
        if reserved {
            let mut bucket = Bucket::full(self.burst, now);
            let verdict = self.take(&mut bucket, now);
            shard.buckets.insert(network, bucket);
            return verdict;
        }
        drop(shard);

        self.take(&mut lock(&self.overflow), now)
    }

    /// Counts one more tracked network, unless the table is full.
    fn reserve(&self) -> bool {
        self.tracked
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < self.max_tracked).then_some(n + 1)
            })
            .is_ok()
    }

    /// Forgets the networks in `shard` whose buckets have filled up again:
    /// they are the same as a new entry.
    fn sweep(&self, shard: &mut Shard, now: Instant) {
        let before = shard.buckets.len();
        shard.buckets.retain(|_, bucket| !self.is_full(bucket, now));
        self.tracked
            .fetch_sub(before - shard.buckets.len(), Ordering::Relaxed);
        shard.last_sweep = now;
    }

    /// Whether `bucket` would be full again at `now`.
    fn is_full(&self, bucket: &Bucket, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens + elapsed * self.rate >= self.burst
    }

    /// The client's network address, used as the bucket key.
    pub fn network(&self, client: IpAddr) -> IpAddr {
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
        // `now` is read before the lock is taken, so a request that waited
        // for the lock can carry an older time than the last update.
        // Never move `updated` backward, or the next request would be
        // credited part of the same interval a second time.
        let now = now.max(bucket.updated);
        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
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

    /// The `i`-th of many IPv4 networks (/24s).
    fn network(i: usize) -> IpAddr {
        let [_, a, b, c] = u32::try_from(i).unwrap().to_be_bytes();
        IpAddr::V4(Ipv4Addr::new(10 + a, b, c, 1))
    }

    #[test]
    fn full_table_shares_one_bucket() {
        let rl = limiter(RateLimitConfig {
            max_tracked: 32,
            ..cfg(1, 1, 0)
        });
        let now = Instant::now();
        let allowed = (0..1024)
            .filter(|i| rl.check_at(network(*i), now) == Verdict::Allow)
            .count();
        // Every tracked network got its one token; all the others shared one.
        assert_eq!(rl.tracked(), 32);
        assert_eq!(allowed, 32 + 1);
    }

    #[test]
    fn tables_fill_up_before_networks_share_a_bucket() {
        // Small tables are one part, bigger ones several; either way every
        // entry is used before new networks overflow.
        for max_tracked in [1, 63, 1000, 4096, 5000] {
            let rl = limiter(RateLimitConfig {
                max_tracked,
                ..cfg(1, 1, 0)
            });
            let now = Instant::now();
            let allowed = (0..max_tracked + 100)
                .filter(|i| rl.check_at(network(*i), now) == Verdict::Allow)
                .count();
            assert_eq!(rl.tracked(), max_tracked, "{max_tracked}");
            assert_eq!(allowed, max_tracked + 1, "{max_tracked}");
        }
    }

    #[test]
    fn full_table_overflows_only_while_every_network_is_active() {
        let rl = limiter(RateLimitConfig {
            max_tracked: 4,
            ..cfg(1, 2, 0)
        });
        // Late enough that the table may be swept at once.
        let t0 = Instant::now() + Duration::from_secs(1);
        for i in 0..4 {
            assert_eq!(rl.check_at(network(i), t0), Verdict::Allow);
        }
        // No bucket is full again yet, so every tracked network is active
        // and new networks share the overflow bucket.
        let t1 = t0 + Duration::from_millis(500);
        for i in 0..3 {
            assert_eq!(rl.check_at(network(i), t1), Verdict::Allow);
        }
        assert_eq!(rl.check_at(network(10), t1), Verdict::Allow);
        assert_eq!(rl.check_at(network(10), t1), Verdict::Allow);
        assert_eq!(rl.check_at(network(11), t1), Verdict::Drop);
        assert_eq!(rl.tracked(), 4);

        // Network 3 has been idle for a second, so its bucket is full
        // again and a new network takes its place, with a bucket of its
        // own. The others still have state worth keeping.
        let t2 = t0 + Duration::from_secs(1);
        assert_eq!(rl.check_at(network(12), t2), Verdict::Allow);
        assert_eq!(rl.check_at(network(12), t2), Verdict::Allow);
        assert_eq!(rl.check_at(network(12), t2), Verdict::Drop);
        assert_eq!(rl.tracked(), 4);
        assert_eq!(rl.check_at(network(0), t2), Verdict::Allow);
        assert_eq!(rl.check_at(network(0), t2), Verdict::Drop);
    }

    #[test]
    fn refilled_buckets_are_reclaimed() {
        let rl = limiter(RateLimitConfig {
            max_tracked: 1000,
            ..cfg(1, 1, 0)
        });
        let t0 = Instant::now();
        for i in 0..1000 {
            assert_eq!(rl.check_at(network(i), t0), Verdict::Allow);
        }
        assert_eq!(rl.check_at(network(1000), t0), Verdict::Allow);
        assert_eq!(rl.check_at(network(1001), t0), Verdict::Drop);

        // A second later every bucket is full again, so another thousand
        // networks get buckets of their own.
        let t1 = t0 + Duration::from_secs(1);
        let allowed = (2000..3000)
            .filter(|i| rl.check_at(network(*i), t1) == Verdict::Allow)
            .count();
        assert_eq!(allowed, 1000);
        assert_eq!(rl.tracked(), 1000);
    }

    #[test]
    fn a_late_request_does_not_move_time_backward() {
        let rl = limiter(cfg(10, 1, 0));
        let start = Instant::now();
        let client = ip("192.0.2.1");
        assert_eq!(rl.check_at(client, start), Verdict::Allow);
        let t100 = start + Duration::from_millis(100);
        assert_eq!(rl.check_at(client, t100), Verdict::Allow);
        // A request stamped earlier that got the lock late.
        assert_eq!(
            rl.check_at(client, start + Duration::from_millis(50)),
            Verdict::Drop
        );
        // Only 50 ms since the last token was taken: half a token, not one.
        let t150 = start + Duration::from_millis(150);
        assert_eq!(rl.check_at(client, t150), Verdict::Drop);
        let t250 = start + Duration::from_millis(250);
        assert_eq!(rl.check_at(client, t250), Verdict::Allow);
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
