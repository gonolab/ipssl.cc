//! Signatures on the writes between the API and the name servers, with
//! the shared secret in `acme.key`.
//!
//! The API signs each write with HMAC-SHA256 over the name server's
//! endpoint as the API addresses it (the `Host` header), the time, the
//! method, the path and the body, which holds the change's sequence
//! number, and sends the time and the MAC in two headers:
//!
//! ```text
//! Host:         198.51.100.1:8053
//! X-Ipssl-Time: 1763540000
//! X-Ipssl-Mac:  <64 hex digits>
//! MAC = HMAC(key, "ipssl-acme-v1 request\n" host "\n" time "\n" method "\n" path "\n" body)
//! ```
//!
//! The endpoint makes the same change sent to two name servers, or to one
//! name server at two addresses, two different requests. A name server
//! with the key takes a write only if the MAC is right, the time is within
//! [`MAX_SKEW`] of its own clock, and it has not taken the same write
//! before (nor, right after a restart, one signed before it started). It does not check the endpoint against its own addresses: behind
//! NAT it does not know the one the API uses. It signs its answer, bound
//! to the endpoint and to the request's MAC, so the API can tell it from a
//! forged one, and from another name server's answer to the same change:
//!
//! ```text
//! X-Ipssl-Mac:  <64 hex digits>
//! MAC = HMAC(key, "ipssl-acme-v1 reply\n" host "\n" request-MAC-in-hex "\n" status "\n" body)
//! ```
//!
//! A name server without a key ignores the headers and does not sign.

use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use data_encoding::{HEXLOWER, HEXLOWER_PERMISSIVE};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use super::error;
use crate::http::{Request, Response};

/// The header with the time a request was signed, in Unix seconds.
pub const TIME: &str = "X-Ipssl-Time";

/// The header with a request's or an answer's MAC, in hex.
pub const MAC: &str = "X-Ipssl-Mac";

/// Most seconds a signed request's time may be off the name server's
/// clock, either way. The API signs right before it sends, so this only
/// has to cover the difference between the clocks.
const MAX_SKEW: i64 = 30;

/// How long a signed request stays fresh at most, from the moment a name
/// server takes it: [`MAX_SKEW`] either side of its time. Measured on the
/// monotonic clock, which NTP does not step.
const FRESH_FOR: Duration = Duration::from_secs(2 * MAX_SKEW as u64);

/// Most signed requests a name server remembers to refuse them a second
/// time, see [`Recent`]. Far more than the API sends in a minute.
const MAX_RECENT: usize = 100_000;

/// A MAC.
pub type Tag = [u8; 32];

/// A signed request, as far as its answer is bound to it: the endpoint it
/// went to and its MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    host: String,
    mac: Tag,
}

/// The shared secret, ready to sign and verify.
#[derive(Clone)]
pub struct Key(Hmac<Sha256>);

impl Key {
    pub fn new(secret: &[u8]) -> Self {
        Self(Hmac::new_from_slice(secret).expect("HMAC takes keys of any length"))
    }

    fn sign(&self, message: &[u8]) -> Tag {
        let mut mac = self.0.clone();
        mac.update(message);
        let tag = mac.finalize().into_bytes();
        tag.as_slice().try_into().expect("SHA-256 has 32 bytes")
    }

    /// Whether `tag` is the MAC of `message`, compared in constant time.
    fn verifies(&self, message: &[u8], tag: &[u8]) -> bool {
        let mut mac = self.0.clone();
        mac.update(message);
        mac.verify_slice(tag).is_ok()
    }

    /// The headers that sign a request made at `time` to `host`, the
    /// endpoint the request goes to as its `Host` header names it, and
    /// the signed request, which the answer is bound to.
    pub fn sign_request(
        &self,
        host: &str,
        time: i64,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> (Vec<(&'static str, String)>, Signed) {
        let mac = self.sign(&request_message(host, time, method, path, body));
        let headers = vec![(TIME, time.to_string()), (MAC, HEXLOWER.encode(&mac))];
        let host = host.to_owned();
        (headers, Signed { host, mac })
    }

    /// Adds the MAC that binds `response` to the `request` it answers.
    pub fn sign_response(&self, request: &Signed, response: Response) -> Response {
        let message = reply_message(request, response.status, response.body.as_bytes());
        let mac = HEXLOWER.encode(&self.sign(&message));
        response.with_header(MAC, mac)
    }

    /// Whether `mac` (hex) is this key's MAC of an answer with `status` and
    /// `body` to `request`. In constant time.
    pub fn verifies_reply(&self, request: &Signed, status: u16, body: &[u8], mac: &str) -> bool {
        let Ok(mac) = HEXLOWER_PERMISSIVE.decode(mac.as_bytes()) else {
            return false;
        };
        self.verifies(&reply_message(request, status, body), &mac)
    }
}

fn request_message(host: &str, time: i64, method: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut message =
        format!("ipssl-acme-v1 request\n{host}\n{time}\n{method}\n{path}\n").into_bytes();
    message.extend_from_slice(body);
    message
}

fn reply_message(request: &Signed, status: u16, body: &[u8]) -> Vec<u8> {
    let (host, mac) = (&request.host, HEXLOWER.encode(&request.mac));
    let mut message = format!("ipssl-acme-v1 reply\n{host}\n{mac}\n{status}\n").into_bytes();
    message.extend_from_slice(body);
    message
}

/// The current time in Unix seconds.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// What a name server with a key checks every write against.
pub struct Guard {
    key: Key,
    /// When the name server started, by the wall clock. What the process
    /// before it took is gone from [`Recent`], so for [`FRESH_FOR`] after
    /// the start it takes nothing signed before then; past that, such a
    /// request is stale anyway.
    started: i64,
    /// When the name server started, by the monotonic clock. A wall clock
    /// that NTP steps back after the start (one that was fast at boot)
    /// would otherwise refuse every write until it caught up again.
    started_at: Instant,
    recent: Mutex<Recent>,
}

impl Guard {
    pub fn new(key: Key) -> Self {
        Self {
            key,
            started: now(),
            started_at: Instant::now(),
            recent: Mutex::default(),
        }
    }

    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Checks that `req` is signed with the key, recently, and new; returns
    /// it as signed, or the answer that refuses it.
    pub fn check(&self, req: &Request) -> Result<Signed, Response> {
        self.check_at(req, now(), Instant::now())
    }

    /// [`Guard::check`] at the wall-clock time `now` and the monotonic
    /// time `at`.
    fn check_at(&self, req: &Request, now: i64, at: Instant) -> Result<Signed, Response> {
        let refuse = |message: &str| error(401, message);
        let host = req.header("host");
        let time = req.header(TIME).and_then(|t| t.parse::<i64>().ok());
        let mac = req
            .header(MAC)
            .and_then(|m| HEXLOWER_PERMISSIVE.decode(m.as_bytes()).ok());
        let (Some(host), Some(time), Some(mac)) = (host, time, mac) else {
            return Err(refuse(
                "not signed: this name server has acme.key, so the API needs it too",
            ));
        };
        let message = request_message(host, time, &req.method, &req.path, &req.body);
        if !self.key.verifies(&message, &mac) {
            return Err(refuse(
                "bad signature: acme.key differs between the API and this name server",
            ));
        }
        let mac: Tag = mac.try_into().expect("verified, so 32 bytes");
        let age = now - time;
        if age.abs() > MAX_SKEW {
            return Err(refuse(&format!(
                "signed {age} s from now by this name server's clock, more than {MAX_SKEW} s off; \
                 check that the clocks agree"
            )));
        }
        if time < self.started && at.saturating_duration_since(self.started_at) < FRESH_FOR {
            return Err(refuse("signed before this name server started"));
        }
        self.lock().insert(mac, time, now, at)?;
        let host = host.to_owned();
        Ok(Signed { host, mac })
    }

    fn lock(&self) -> MutexGuard<'_, Recent> {
        self.recent.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The MACs of the signed requests taken while they are fresh, so that a
/// copy of one is refused. A MAC is kept while the request's time is
/// within [`MAX_SKEW`] of the clock, and in any case for [`FRESH_FOR`]
/// after it was taken: a wall clock stepped back meanwhile makes an old
/// request fresh again.
#[derive(Default)]
struct Recent {
    seen: HashSet<Tag>,
    /// Each MAC in `seen` with the time it was signed and when it was
    /// taken, in the order taken.
    order: VecDeque<(i64, Instant, Tag)>,
}

impl Recent {
    fn insert(&mut self, mac: Tag, time: i64, now: i64, at: Instant) -> Result<(), Response> {
        // Requests arrive about in the order of their times. One that is
        // stale but behind a fresh one stays a little longer, which is
        // harmless; none goes before it is stale.
        while let Some(&(signed, taken, old)) = self.order.front()
            && now - signed > MAX_SKEW
            && at.saturating_duration_since(taken) >= FRESH_FOR
        {
            self.order.pop_front();
            self.seen.remove(&old);
        }
        if self.seen.contains(&mac) {
            return Err(error(401, "this request was taken already"));
        }
        if self.seen.len() >= MAX_RECENT {
            return Err(error(503, "too many writes, try again later"));
        }
        self.seen.insert(mac);
        self.order.push_back((time, at, mac));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "198.51.100.1:8053";

    fn request(key: &Key, time: i64, path: &str, body: &str) -> (Request, Signed) {
        let (headers, signed) = key.sign_request(HOST, time, "POST", path, body.as_bytes());
        let headers = headers
            .into_iter()
            .chain([("Host", HOST.to_owned())])
            .map(|(n, v)| (n.to_ascii_lowercase(), v))
            .collect();
        let peer = "127.0.0.1:1".parse().unwrap();
        let req = Request::new("POST", path, peer, headers, body.as_bytes().to_vec());
        (req, signed)
    }

    #[test]
    fn mac_is_hmac_sha256() {
        // RFC 4231, test case 2.
        let tag = Key::new(b"Jefe").sign(b"what do ya want for nothing?");
        assert_eq!(
            HEXLOWER.encode(&tag),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert!(Key::new(b"Jefe").verifies(b"what do ya want for nothing?", &tag));
        assert!(!Key::new(b"Jefe").verifies(b"what do ya want for nothing?", &tag[..31]));
    }

    #[test]
    fn signed_requests_and_answers_verify() {
        let key = Key::new(&[7; 32]);
        let guard = Guard::new(key.clone());
        let now = guard.started;
        let (req, signed) = request(&key, now, "/present", "{}");
        assert_eq!(guard.check_at(&req, now, guard.started_at).unwrap(), signed);

        let answer = key.sign_response(&signed, Response::new(200, "application/json", "{}"));
        let signature = answer.headers[0].1.clone();
        assert!(key.verifies_reply(&signed, 200, b"{}", &signature));
        // Bound to the request, the endpoint, the status and the body.
        let other = Signed {
            mac: [0; 32],
            ..signed.clone()
        };
        assert!(!key.verifies_reply(&other, 200, b"{}", &signature));
        let elsewhere = Signed {
            host: "198.51.100.2:8053".to_owned(),
            ..signed.clone()
        };
        assert!(!key.verifies_reply(&elsewhere, 200, b"{}", &signature));
        assert!(!key.verifies_reply(&signed, 409, b"{}", &signature));
        assert!(!key.verifies_reply(&signed, 200, b"{ }", &signature));
        assert!(!Key::new(&[8; 32]).verifies_reply(&signed, 200, b"{}", &signature));
        assert!(!key.verifies_reply(&signed, 200, b"{}", "not hex"));
    }

    #[test]
    fn the_same_change_to_two_endpoints_is_two_requests() {
        let key = Key::new(&[7; 32]);
        let (_, one) = key.sign_request("198.51.100.1:8053", 1, "POST", "/present", b"{}");
        let (_, two) = key.sign_request("[2001:db8::1]:8053", 1, "POST", "/present", b"{}");
        assert_ne!(one.mac, two.mac);
    }

    #[test]
    fn requests_must_be_signed_fresh_and_new() {
        let key = Key::new(&[7; 32]);
        let guard = Guard::new(key.clone());
        let now = guard.started + 100;
        let later = guard.started_at + Duration::from_secs(100);
        let status = |req: &Request, now: i64| {
            let at = later + Duration::from_secs((now - guard.started - 100).max(0) as u64);
            guard.check_at(req, now, at).err().map(|r| r.status)
        };

        let (req, _) = request(&key, now, "/present", "{}");
        assert_eq!(status(&req, now), None);
        assert_eq!(status(&req, now), Some(401), "replayed");

        // Another key, another path, another body, no signature.
        let (other, _) = request(&Key::new(&[8; 32]), now, "/present", "{}");
        assert_eq!(status(&other, now), Some(401));
        let (mut redirected, _) = request(&key, now, "/present", "{\"a\":0}");
        redirected.set_header("host", "198.51.100.2:8053");
        assert_eq!(status(&redirected, now), Some(401));
        let (mut moved, _) = request(&key, now, "/present", "{\"a\":1}");
        moved.path = "/cleanup".to_owned();
        assert_eq!(status(&moved, now), Some(401));
        let (mut changed, _) = request(&key, now, "/present", "{\"a\":2}");
        changed.body = b"{\"a\":3}".to_vec();
        assert_eq!(status(&changed, now), Some(401));
        let peer = "127.0.0.1:1".parse().unwrap();
        let bare = Request::new("POST", "/present", peer, Vec::new(), b"{}".to_vec());
        assert_eq!(status(&bare, now), Some(401));

        // Too old or too far ahead.
        for time in [now - MAX_SKEW - 1, now + MAX_SKEW + 1] {
            let (req, _) = request(&key, time, "/present", "{\"b\":1}");
            assert_eq!(status(&req, now), Some(401), "{time}");
        }
        let (edge, _) = request(&key, now - MAX_SKEW, "/present", "{\"c\":1}");
        assert_eq!(status(&edge, now), None);

        // Right after the start, from before it: the process before may
        // have taken it.
        let (early, _) = request(&key, guard.started - 1, "/present", "{\"d\":1}");
        let started = guard.started_at;
        let refused = guard.check_at(&early, guard.started, started);
        assert_eq!(refused.err().map(|r| r.status), Some(401));
    }

    #[test]
    fn a_clock_stepped_back_after_start_refuses_writes_only_briefly() {
        // The name server started with its clock 120 s fast, and NTP then
        // set it right: requests signed now are "before the start".
        let key = Key::new(&[7; 32]);
        let guard = Guard::new(key.clone());
        let real = guard.started - 120;
        let status = |req: &Request, now: i64, uptime: u64| {
            let at = guard.started_at + Duration::from_secs(uptime);
            guard.check_at(req, now, at).err().map(|r| r.status)
        };
        let (soon, _) = request(&key, real + 10, "/present", "{}");
        assert_eq!(status(&soon, real + 10, 10), Some(401));
        // Once a request from before the start is stale anyway, they pass.
        let uptime = FRESH_FOR.as_secs();
        let (later, _) = request(&key, real + 60, "/present", "{}");
        assert_eq!(status(&later, real + 60, uptime), None);
        assert_eq!(
            status(&later, real + 60, uptime),
            Some(401),
            "taken already"
        );
    }

    #[test]
    fn recent_requests_are_forgotten_once_stale() {
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        let mut recent = Recent::default();
        recent.insert([1; 32], 1000, 1000, at(0)).unwrap();
        recent.insert([2; 32], 1010, 1010, at(10)).unwrap();
        assert!(
            recent
                .insert([1; 32], 1000, 1000 + MAX_SKEW, at(30))
                .is_err()
        );
        // Stale by the clock, but taken too recently: a clock stepped
        // back could make it fresh again.
        recent.insert([3; 32], 1031, 1031, at(31)).unwrap();
        assert!(recent.seen.contains(&[1; 32]));
        // Stale and taken long enough ago: forgotten.
        recent.insert([4; 32], 1060, 1060, at(60)).unwrap();
        assert!(!recent.seen.contains(&[1; 32]));
        assert!(recent.seen.contains(&[2; 32]));
        assert_eq!(recent.seen.len(), recent.order.len());
    }

    #[test]
    fn a_clock_stepped_back_does_not_make_a_copy_fresh() {
        let start = Instant::now();
        let mut recent = Recent::default();
        // Taken while the clock was 20 s fast (the real time is 1000).
        recent.insert([1; 32], 1000, 1020, start).unwrap();
        // 12 s later the fast clock makes it stale, but it was taken too
        // recently to be forgotten...
        let later = start + Duration::from_secs(12);
        recent.insert([2; 32], 1012, 1032, later).unwrap();
        assert!(recent.seen.contains(&[1; 32]));
        // ...so once NTP steps the clock back, a copy is still refused,
        // although its time is fresh again.
        let stepped = start + Duration::from_secs(13);
        assert!(recent.insert([1; 32], 1000, 1013, stepped).is_err());
    }
}
