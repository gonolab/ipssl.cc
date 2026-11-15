//! Answers queries for the zone. Pure logic with no I/O, so it is easy to test.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use anyhow::{Context, Result, bail, ensure};
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::rdata::{A, AAAA, CAA, MX, NS, SOA, TXT};
use hickory_server::proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use hickory_server::proto::serialize::binary::{BinEncodable, BinEncoder};
use ipnet::IpNet;

use crate::acme::{CHALLENGE_LABEL, is_private};
use crate::config::Config;
use crate::parse::extract_ip;

/// `ip.<domain>` answers TXT queries with the address of whoever asked
/// (usually the user's recursive resolver). Handy for debugging.
const WHOAMI_LABEL: &str = "ip";

/// Largest TTL resolvers take as given (RFC 2181 section 8): above it the
/// top bit is set, and many resolvers then treat the TTL as 0. Also the
/// upper bound of the SOA timers (RFC 1035 section 3.3.13).
const MAX_TTL: u32 = i32::MAX as u32;

/// Largest DNS message. TCP frames each one with a 16-bit length
/// (RFC 1035 section 4.2.2), so a bigger answer cannot be sent at all.
const MAX_MESSAGE: usize = 65_535;

/// The outcome of a lookup, ready to be put into a response message.
#[derive(Debug)]
pub struct Answer {
    pub rcode: ResponseCode,
    pub authoritative: bool,
    pub answers: Vec<Record>,
    /// SOA for the authority section of negative answers.
    pub soa: Option<Record>,
}

pub struct Zone {
    origin: LowerName,
    origin_labels: usize,
    negative_soa: Record,
    /// Fixed records by owner name. The apex is always present, SOA first.
    hosts: HashMap<LowerName, Vec<Record>>,
    /// Names above fixed hosts (`nested.<domain>` for `deep.nested.<domain>`).
    /// They have to exist for the hosts to be found, even when the address
    /// in them is blocked.
    fixed_ancestors: HashSet<LowerName>,
    whoami: LowerName,
    ip_ttl: u32,
    blocklist: Vec<IpNet>,
    serial: u32,
}

impl Zone {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let origin = fqdn(&cfg.domain).context("invalid `domain`")?;
        // An empty `domain` would make this server claim the whole DNS.
        ensure!(!origin.is_root(), "`domain` must not be empty");
        ensure!(
            !cfg.nameservers.is_empty(),
            "at least one entry in `nameservers` is required"
        );
        check_timers(cfg)?;
        let ttl = cfg.ttl.records;
        let mut hosts: HashMap<LowerName, Vec<Record>> = HashMap::new();

        // Apex: SOA, NS, CAA.
        let soa = SOA::new(
            fqdn(&cfg.nameservers[0].name)?,
            email_to_name(&cfg.soa.email)?,
            cfg.soa.serial,
            cfg.soa.refresh,
            cfg.soa.retry,
            cfg.soa.expire,
            cfg.soa.minimum,
        );
        let soa = Record::from_rdata(origin.clone(), ttl, RData::SOA(soa));
        let mut negative_soa = soa.clone();
        negative_soa.ttl = ttl.min(cfg.soa.minimum);

        let apex = hosts.entry(LowerName::new(&origin)).or_default();
        apex.push(soa);
        for ns in &cfg.nameservers {
            let name = fqdn(&ns.name)?;
            apex.push(Record::from_rdata(origin.clone(), ttl, RData::NS(NS(name))));
        }
        for issuer in &cfg.caa_issuers {
            let caa = CAA::new_issue(false, Some(caa_issuer(issuer)?), vec![]);
            apex.push(Record::from_rdata(origin.clone(), ttl, RData::CAA(caa)));
        }

        // Addresses for in-zone name servers.
        let mut in_zone_ns = Vec::new();
        for ns in &cfg.nameservers {
            let name = fqdn(&ns.name)?;
            if !origin.zone_of(&name) {
                ensure!(
                    ns.ipv4.is_empty() && ns.ipv6.is_empty(),
                    "name server {} is outside {}; its addresses would never be served",
                    ns.name,
                    cfg.domain
                );
                continue;
            }
            let records = hosts.entry(LowerName::new(&name)).or_default();
            for ip in &ns.ipv4 {
                records.push(Record::from_rdata(name.clone(), ttl, RData::A(A(*ip))));
            }
            for ip in &ns.ipv6 {
                records.push(Record::from_rdata(
                    name.clone(),
                    ttl,
                    RData::AAAA(AAAA(*ip)),
                ));
            }
            in_zone_ns.push((ns.name.as_str(), LowerName::new(&name)));
        }

        // Fixed hosts from the config.
        let mut host_labels: HashMap<LowerName, &str> = HashMap::new();
        for (label, host) in &cfg.hosts {
            let name = host_name(label, &cfg.domain, &origin)?;
            // Owner names ignore case, so `MailAlias` and `mailalias` would
            // become one name and slip past the per-host checks below.
            if let Some(other) = host_labels.insert(LowerName::new(&name), label) {
                bail!(
                    "hosts {other:?} and {label:?} are the same name (DNS names ignore case); merge them"
                );
            }
            let records = hosts.entry(LowerName::new(&name)).or_default();
            for ip in &host.a {
                records.push(Record::from_rdata(name.clone(), ttl, RData::A(A(*ip))));
            }
            for ip in &host.aaaa {
                records.push(Record::from_rdata(
                    name.clone(),
                    ttl,
                    RData::AAAA(AAAA(*ip)),
                ));
            }
            for txt in &host.txt {
                let data = RData::TXT(txt_record(txt));
                records.push(Record::from_rdata(name.clone(), ttl, data));
            }
            let mut exchanges = Vec::with_capacity(host.mx.len());
            for mx in &host.mx {
                let exchange = mx.exchange.trim();
                // Without its final dot, `192.0.2.15.` is an address too.
                ensure!(
                    exchange.trim_end_matches('.').parse::<IpAddr>().is_err(),
                    "host {label:?}: MX exchange must be a host name, not an address: {exchange}"
                );
                let target = fqdn(exchange)
                    .with_context(|| format!("host {label:?}: invalid MX exchange"))?;
                exchanges.push((mx.preference, target));
            }
            // An exchange of `.` is a null MX (RFC 7505).
            let null_mx = exchanges.iter().any(|(_, target)| target.is_root());
            ensure!(
                !null_mx || (exchanges.len() == 1 && exchanges[0].0 == 0),
                "host {label:?}: a null MX (exchange \".\") must be the only MX and have preference 0"
            );
            for (preference, exchange) in exchanges {
                let data = RData::MX(MX::new(preference, exchange));
                records.push(Record::from_rdata(name.clone(), ttl, data));
            }
        }

        // An RRset holds each record once (RFC 2181 section 5), even when it
        // is configured twice, e.g. a name server address repeated under
        // [hosts].
        for records in hosts.values_mut() {
            let mut unique: Vec<Record> = Vec::with_capacity(records.len());
            for record in records.drain(..) {
                if !unique.contains(&record) {
                    unique.push(record);
                }
            }
            *records = unique;
        }

        // Resolvers can only reach an in-zone name server through the
        // addresses served here.
        for (label, name) in &in_zone_ns {
            ensure!(
                hosts[name].iter().any(is_address),
                "name server {label} is inside {} but has no address; give it ipv4 or ipv6",
                cfg.domain
            );
        }

        for records in hosts.values() {
            check_sizes(records)?;
        }

        let origin_lower = LowerName::new(&origin);
        let mut fixed_ancestors = HashSet::new();
        for owner in hosts.keys() {
            let mut name = owner.base_name();
            while name != origin_lower && origin_lower.zone_of(&name) {
                let parent = name.base_name();
                fixed_ancestors.insert(name);
                name = parent;
            }
        }

        let whoami = fqdn(&format!(
            "{WHOAMI_LABEL}.{}",
            cfg.domain.trim_end_matches('.')
        ))?;

        Ok(Self {
            origin_labels: origin.iter().count(),
            origin: origin_lower,
            negative_soa,
            hosts,
            fixed_ancestors,
            whoami: LowerName::new(&whoami),
            ip_ttl: cfg.ttl.ip,
            blocklist: cfg.blocklist.clone(),
            serial: cfg.soa.serial,
        })
    }

    /// The SOA serial.
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Looks up `qname`. `client` is the address the query came from.
    pub fn resolve(
        &self,
        qname: &Name,
        qtype: RecordType,
        qclass: DNSClass,
        client: IpAddr,
    ) -> Answer {
        let lower = LowerName::new(qname);
        if qclass != DNSClass::IN || !self.origin.zone_of(&lower) {
            return Answer::refused();
        }
        // No zone transfers: most of the zone is computed from the names,
        // so there is nothing to transfer.
        if matches!(qtype, RecordType::AXFR | RecordType::IXFR) {
            return Answer::refused();
        }

        if let Some(records) = self.hosts.get(&lower) {
            return self.fixed(qname, records, qtype);
        }

        if lower == self.whoami {
            return match qtype {
                RecordType::TXT | RecordType::ANY => {
                    let txt = TXT::new(vec![client.to_canonical().to_string()]);
                    self.answer(vec![Record::from_rdata(qname.clone(), 0, RData::TXT(txt))])
                }
                _ => self.nodata(),
            };
        }

        match self.embedded_ip(qname) {
            // A blocked name does not exist, and neither do the names below
            // it, which hold the same address. Names above fixed hosts are
            // kept, or the hosts could not be found.
            Some(ip) if self.is_blocked(ip) => {
                if self.fixed_ancestors.contains(&lower) {
                    self.nodata()
                } else {
                    self.nxdomain()
                }
            }
            Some(ip) => self.address(qname, qtype, ip),
            // Every other name exists, with or without records: any name
            // can have names with addresses below it (`1.<domain>` is above
            // `10.0.0.1.<domain>`, `app.<domain>` above
            // `10-0-0-1.app.<domain>`), and NXDOMAIN would tell resolvers
            // that none of them exist (RFC 8020).
            None => self.nodata(),
        }
    }

    /// Parses `fqdn` (the trailing dot is optional) and checks that it can
    /// hold a DNS-01 challenge, see [`Self::check_challenge`].
    pub fn challenge_name(&self, fqdn: &str) -> Result<LowerName, ChallengeError> {
        let trimmed = fqdn.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return Err(ChallengeError::Invalid);
        }
        let name = Name::from_ascii(format!("{trimmed}.")).map_err(|_| ChallengeError::Invalid)?;
        self.check_challenge(&name)?;
        Ok(LowerName::new(&name))
    }

    /// Checks that `name` is `_acme-challenge.<name>` in this zone, where
    /// `<name>` holds a private address. Public addresses are left to
    /// HTTP-01 and TLS-ALPN-01, which only whoever holds the address can
    /// pass; letting anyone publish challenges for them would let anyone
    /// get a certificate for someone else's server.
    pub fn check_challenge(&self, name: &Name) -> Result<IpAddr, ChallengeError> {
        if !self.origin.zone_of(&LowerName::new(name)) {
            return Err(ChallengeError::OutsideZone);
        }
        let labels = self.relative_labels(name);
        let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
        match labels.split_first() {
            Some((&CHALLENGE_LABEL, rest)) => {
                let ip = extract_ip(rest).ok_or(ChallengeError::NoAddress)?;
                if self.is_blocked(ip) {
                    Err(ChallengeError::Blocked)
                } else if !is_private(ip) {
                    Err(ChallengeError::PublicAddress)
                } else {
                    Ok(ip)
                }
            }
            _ => Err(ChallengeError::NotChallenge),
        }
    }

    /// The answer to a TXT query for a challenge name, given the values
    /// published for it. Everything has TTL 0, the negative answer
    /// included, so a client that retries is never answered from a cache.
    pub fn challenge_answer(&self, qname: &Name, values: Vec<String>) -> Answer {
        if values.is_empty() {
            let mut soa = self.negative_soa.clone();
            soa.ttl = 0;
            return Answer {
                soa: Some(soa),
                ..self.nodata()
            };
        }
        let answers = values
            .into_iter()
            .map(|v| Record::from_rdata(qname.clone(), 0, RData::TXT(TXT::new(vec![v]))))
            .collect();
        self.answer(answers)
    }

    /// The lowercase labels of `name` left of the apex, in normal order.
    /// `name` must be inside the zone.
    fn relative_labels(&self, name: &Name) -> Vec<String> {
        // Not `num_labels()`, which leaves out a leading `*`.
        let relative = name.iter().count() - self.origin_labels;
        name.iter()
            .take(relative)
            .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
            .collect()
    }

    /// The address embedded in `name`, which must be inside the zone.
    fn embedded_ip(&self, name: &Name) -> Option<IpAddr> {
        let labels = self.relative_labels(name);
        let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
        extract_ip(&labels)
    }

    /// Whether `ip` is blocked. An IPv4-mapped IPv6 address
    /// (`::ffff:10.9.0.1`) also counts as the IPv4 address it holds.
    fn is_blocked(&self, ip: IpAddr) -> bool {
        let canonical = ip.to_canonical();
        self.blocklist
            .iter()
            .any(|net| net.contains(&ip) || net.contains(&canonical))
    }

    fn fixed(&self, qname: &Name, records: &[Record], qtype: RecordType) -> Answer {
        // RFC 8482: answer ANY with one RRset instead of everything.
        let wanted = match (qtype, records.first()) {
            (RecordType::ANY, Some(first)) => first.record_type(),
            (qtype, _) => qtype,
        };
        let matched: Vec<Record> = records
            .iter()
            .filter(|r| r.record_type() == wanted)
            .map(|r| {
                let mut r = r.clone();
                r.name = qname.clone();
                r
            })
            .collect();
        if !matched.is_empty() {
            return self.answer(matched);
        }
        // A host with no address of the asked type (say, only a TXT record
        // for a site verification) keeps the address its name holds.
        if matches!(qtype, RecordType::A | RecordType::AAAA | RecordType::ANY)
            && let Some(ip) = self.embedded_ip(qname)
            && !self.is_blocked(ip)
        {
            return self.address(qname, qtype, ip);
        }
        self.nodata()
    }

    /// The answer from the address embedded in `qname`.
    fn address(&self, qname: &Name, qtype: RecordType, ip: IpAddr) -> Answer {
        let data = match ip {
            IpAddr::V4(ip) if matches!(qtype, RecordType::A | RecordType::ANY) => RData::A(A(ip)),
            IpAddr::V6(ip) if matches!(qtype, RecordType::AAAA | RecordType::ANY) => {
                RData::AAAA(AAAA(ip))
            }
            _ => return self.nodata(),
        };
        self.answer(vec![Record::from_rdata(qname.clone(), self.ip_ttl, data)])
    }

    fn answer(&self, answers: Vec<Record>) -> Answer {
        Answer {
            rcode: ResponseCode::NoError,
            authoritative: true,
            answers,
            soa: None,
        }
    }

    fn nodata(&self) -> Answer {
        Answer {
            rcode: ResponseCode::NoError,
            authoritative: true,
            answers: vec![],
            soa: Some(self.negative_soa.clone()),
        }
    }

    fn nxdomain(&self) -> Answer {
        Answer {
            rcode: ResponseCode::NXDomain,
            authoritative: true,
            answers: vec![],
            soa: Some(self.negative_soa.clone()),
        }
    }
}

/// Why a name cannot hold a DNS-01 challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeError {
    Invalid,
    OutsideZone,
    NotChallenge,
    NoAddress,
    PublicAddress,
    Blocked,
}

impl ChallengeError {
    /// Explanation for API clients.
    pub fn message(self) -> &'static str {
        match self {
            Self::Invalid => "fqdn is not a valid domain name",
            Self::OutsideZone => "fqdn is outside this zone",
            Self::NotChallenge => "fqdn must start with _acme-challenge.",
            Self::NoAddress => "fqdn holds no IP address",
            Self::PublicAddress => {
                "only names with private addresses can use DNS-01; validate public addresses with HTTP-01 or TLS-ALPN-01"
            }
            Self::Blocked => "this address is blocked",
        }
    }
}

impl Answer {
    /// A non-authoritative answer with no records.
    pub fn error(rcode: ResponseCode) -> Self {
        Self {
            rcode,
            authoritative: false,
            answers: vec![],
            soa: None,
        }
    }

    fn refused() -> Self {
        Self::error(ResponseCode::Refused)
    }
}

fn is_address(record: &Record) -> bool {
    matches!(record.record_type(), RecordType::A | RecordType::AAAA)
}

/// TTLs and SOA timers are 31-bit numbers on the wire; the timers must
/// also be positive. The TTLs are `u32` and the timers `i32` in the
/// config, so a negative timer would go out as a huge unsigned number.
fn check_timers(cfg: &Config) -> Result<()> {
    for (setting, value) in [
        ("ttl.ip", cfg.ttl.ip),
        ("ttl.records", cfg.ttl.records),
        ("soa.minimum", cfg.soa.minimum),
    ] {
        ensure!(
            value <= MAX_TTL,
            "{setting} must be at most {MAX_TTL} seconds"
        );
    }
    for (setting, value) in [
        ("soa.refresh", cfg.soa.refresh),
        ("soa.retry", cfg.soa.retry),
        ("soa.expire", cfg.soa.expire),
    ] {
        ensure!(
            value >= 1,
            "{setting} must be between 1 and {MAX_TTL} seconds"
        );
    }
    Ok(())
}

/// Checks that every RRset in `records`, which share one owner, fits in a
/// DNS message, so it can at least be sent over TCP.
fn check_sizes(records: &[Record]) -> Result<()> {
    let mut checked = Vec::new();
    for record in records {
        let rtype = record.record_type();
        if checked.contains(&rtype) {
            continue;
        }
        checked.push(rtype);
        let rrset: Vec<&Record> = records
            .iter()
            .filter(|r| r.record_type() == rtype)
            .collect();
        ensure!(
            response_len(&record.name, &rrset).is_some_and(|len| len <= MAX_MESSAGE),
            "{}: the {rtype} records do not fit in a DNS message ({MAX_MESSAGE} bytes); make them shorter or fewer",
            record.name
        );
    }
    Ok(())
}

/// Size of a response that answers a question for `owner` with `records`:
/// the header, the question, the records and an OPT record without
/// options, laid out the way the handler sends it. `None` if a record
/// cannot be encoded at all.
fn response_len(owner: &Name, records: &[&Record]) -> Option<usize> {
    const HEADER_LEN: usize = 12;
    const OPT_LEN: usize = 11;
    // The name as the client sent it, then type and class.
    let question_len = owner.to_bytes().ok()?.len() + 4;
    let mut buf = Vec::new();
    let mut encoder = BinEncoder::new(&mut buf);
    for record in records {
        // `Record::emit` panics on RDATA longer than its 16-bit length
        // field, so measure the RDATA on its own first.
        let mut rdata = Vec::new();
        record.data.emit(&mut BinEncoder::new(&mut rdata)).ok()?;
        if rdata.len() > usize::from(u16::MAX) {
            return None;
        }
        record.emit(&mut encoder).ok()?;
    }
    Some(HEADER_LEN + question_len + encoder.offset() + OPT_LEN)
}

/// Maximum length of one DNS character-string (RFC 1035 section 3.3).
const TXT_CHUNK: usize = 255;

/// A TXT record holding `value`. Longer values are split into 255-byte
/// strings; readers such as DKIM verifiers join them back together.
fn txt_record(value: &str) -> TXT {
    if value.is_empty() {
        return TXT::new(vec![String::new()]);
    }
    TXT::from_bytes(value.as_bytes().chunks(TXT_CHUNK).collect())
}

/// The owner name of the `[hosts]` key `label`; `@` is the apex.
fn host_name(label: &str, domain: &str, origin: &Name) -> Result<Name> {
    if label == "@" {
        return Ok(origin.clone());
    }
    // A `*` label would be served as a literal name, not as a wildcard.
    ensure!(
        !label.contains('*'),
        "host {label:?}: wildcards (`*`) are not supported"
    );
    fqdn(&format!("{label}.{}", domain.trim_end_matches('.')))
        .with_context(|| format!("invalid host {label:?}"))
}

/// Parses `name` as a fully qualified domain name.
fn fqdn(name: &str) -> Result<Name> {
    // hickory decodes `\DDD` escapes as octal where RFC 1035 means decimal
    // (`\101` would become `A`, not `e`), and no configured name needs
    // escapes, so take none.
    ensure!(
        !name.contains('\\'),
        "invalid domain name {name:?}: backslashes are not allowed"
    );
    let name = name.trim_end_matches('.');
    Name::from_ascii(format!("{name}."))
        .map(|n| n.to_lowercase())
        .with_context(|| format!("invalid domain name {name:?}"))
}

/// `hostmaster@ipssl.cc` -> `hostmaster.ipssl.cc.` (the SOA RNAME format).
fn email_to_name(email: &str) -> Result<Name> {
    let (local, domain) = email
        .split_once('@')
        .with_context(|| format!("SOA email {email:?} must look like user@domain"))?;
    ensure!(
        !local.is_empty() && !local.contains('.'),
        "SOA email local part must be non-empty and contain no dots"
    );
    ensure!(
        !domain.trim_end_matches('.').is_empty(),
        "SOA email {email:?} must have a domain after the @"
    );
    fqdn(&format!("{local}.{domain}"))
}

/// A CAA `issue` value: an issuer domain name of letters, digits and
/// inner hyphens (RFC 8659 section 4.2). Generic name parsing would also
/// take `_` and other bytes, which CAs then read as an empty issuer that
/// allows nobody. A trailing dot is dropped.
fn caa_issuer(issuer: &str) -> Result<Name> {
    let domain = issuer.strip_suffix('.').unwrap_or(issuer);
    let ldh = |label: &str| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    ensure!(
        domain.split('.').all(ldh),
        "invalid CAA issuer {issuer:?}: use a domain name of letters, digits and hyphens, such as letsencrypt.org"
    );
    let mut name =
        Name::from_ascii(domain).with_context(|| format!("invalid CAA issuer {issuer:?}"))?;
    name.set_fqdn(false);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HostConfig;
    use std::net::Ipv4Addr;

    const CONFIG: &str = r#"
        domain = "ipssl.cc"
        caa_issuers = ["letsencrypt.org"]
        blocklist = ["203.0.113.0/24"]

        [[nameservers]]
        name = "ns1.ipssl.cc"
        ipv4 = ["198.51.100.1"]
        ipv6 = ["2001:db8::53"]

        [[nameservers]]
        name = "ns2.ipssl.cc"
        ipv4 = ["198.51.100.2"]

        [soa]
        email = "hostmaster@ipssl.cc"

        [hosts."@"]
        a = ["198.51.100.10"]
        mx = [
            { preference = 10, exchange = "mx.example.net." },
            { preference = 20, exchange = "MX2.example.net" },
        ]

        [hosts.www]
        a = ["198.51.100.10"]

        [hosts._dmarc]
        txt = ["v=DMARC1; p=reject"]

        [hosts."deep.nested"]
        a = ["198.51.100.11"]
    "#;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));

    fn config() -> Config {
        Config::parse(CONFIG).unwrap()
    }

    fn zone() -> Zone {
        Zone::from_config(&config()).unwrap()
    }

    fn zone_with(extra: &str) -> Result<Zone> {
        Zone::from_config(&Config::parse(&format!("{CONFIG}\n{extra}\n")).unwrap())
    }

    fn query(name: &str, qtype: RecordType) -> Answer {
        query_zone(&zone(), name, qtype)
    }

    fn query_zone(zone: &Zone, name: &str, qtype: RecordType) -> Answer {
        let name = Name::from_ascii(name).unwrap();
        zone.resolve(&name, qtype, DNSClass::IN, CLIENT)
    }

    fn rdata(answer: &Answer) -> Vec<String> {
        answer.answers.iter().map(|r| r.data.to_string()).collect()
    }

    /// NOERROR with no records and the SOA for negative caching.
    fn is_nodata(answer: &Answer) -> bool {
        answer.rcode == ResponseCode::NoError
            && answer.authoritative
            && answer.answers.is_empty()
            && answer.soa.is_some()
    }

    #[test]
    fn ipv4_name_answers_a() {
        let a = query("app-10-0-0-1.ipssl.cc.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::NoError);
        assert!(a.authoritative);
        assert_eq!(rdata(&a), ["10.0.0.1"]);
        assert_eq!(a.answers[0].ttl, 86_400);
    }

    #[test]
    fn ipv6_name_answers_aaaa() {
        let a = query("2001-db8--1.ipssl.cc.", RecordType::AAAA);
        assert_eq!(rdata(&a), ["2001:db8::1"]);
    }

    #[test]
    fn wrong_family_is_nodata() {
        for (name, qtype) in [
            ("10-0-0-1.ipssl.cc.", RecordType::AAAA),
            ("10-0-0-1.ipssl.cc.", RecordType::TXT),
            ("2001-db8--1.ipssl.cc.", RecordType::A),
        ] {
            assert!(is_nodata(&query(name, qtype)), "{name} {qtype}");
        }
    }

    #[test]
    fn names_without_records_are_nodata() {
        // Any name can have names with addresses below it, so none is
        // NXDOMAIN; otherwise resolvers that minimise queries or follow
        // RFC 8020 would never reach `10.0.0.1.ipssl.cc`.
        for name in [
            "nothing-here.ipssl.cc.",
            "1.ipssl.cc.",
            "0.1.ipssl.cc.",
            "0.0.1.ipssl.cc.",
            "app.ipssl.cc.",
            "x.ip.ipssl.cc.",
        ] {
            let a = query(name, RecordType::A);
            assert!(is_nodata(&a), "{name}");
            assert_eq!(a.soa.unwrap().ttl, 300, "{name}");
        }
        assert_eq!(
            rdata(&query("10.0.0.1.ipssl.cc.", RecordType::A)),
            ["10.0.0.1"]
        );
        assert_eq!(
            rdata(&query("10-0-0-1.app.ipssl.cc.", RecordType::A)),
            ["10.0.0.1"]
        );
    }

    #[test]
    fn outside_zone_is_refused() {
        let a = query("example.com.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::Refused);
        assert!(!a.authoritative);
        let a = query("10-0-0-1.ipssl.cc.evil.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::Refused);
    }

    #[test]
    fn zone_transfers_are_refused() {
        for name in ["ipssl.cc.", "www.ipssl.cc.", "10-0-0-1.ipssl.cc."] {
            for qtype in [RecordType::AXFR, RecordType::IXFR] {
                let a = query(name, qtype);
                assert_eq!(a.rcode, ResponseCode::Refused, "{name} {qtype}");
                assert!(a.answers.is_empty() && a.soa.is_none());
            }
        }
    }

    #[test]
    fn case_is_ignored_and_preserved() {
        let a = query("App-10-0-0-1.IPSSL.cc.", RecordType::A);
        assert_eq!(rdata(&a), ["10.0.0.1"]);
        assert_eq!(a.answers[0].name.to_string(), "App-10-0-0-1.IPSSL.cc.");
    }

    #[test]
    fn leading_wildcard_label_counts() {
        // The address nearest the zone wins, with `*` in front as with
        // any other label.
        for name in [
            "*.10-0-0-2.10-0-0-1.ipssl.cc.",
            "app.10-0-0-2.10-0-0-1.ipssl.cc.",
        ] {
            assert_eq!(rdata(&query(name, RecordType::A)), ["10.0.0.1"], "{name}");
        }
    }

    #[test]
    fn apex_records() {
        assert_eq!(query("ipssl.cc.", RecordType::NS).answers.len(), 2);
        assert_eq!(query("ipssl.cc.", RecordType::SOA).answers.len(), 1);
        assert_eq!(rdata(&query("ipssl.cc.", RecordType::A)), ["198.51.100.10"]);
        assert_eq!(
            rdata(&query("ipssl.cc.", RecordType::CAA)),
            ["0 issue \"letsencrypt.org\""]
        );
        // ANY gets one RRset (the SOA), not everything.
        let any = query("ipssl.cc.", RecordType::ANY);
        assert_eq!(any.answers.len(), 1);
        assert_eq!(any.answers[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn nameserver_glue() {
        assert_eq!(
            rdata(&query("ns1.ipssl.cc.", RecordType::A)),
            ["198.51.100.1"]
        );
        assert_eq!(
            rdata(&query("ns1.ipssl.cc.", RecordType::AAAA)),
            ["2001:db8::53"]
        );
        assert_eq!(
            rdata(&query("ns2.ipssl.cc.", RecordType::A)),
            ["198.51.100.2"]
        );
    }

    #[test]
    fn in_zone_name_servers_need_an_address() {
        let mut cfg = config();
        cfg.nameservers[1].ipv4.clear();
        let err = Zone::from_config(&cfg).err().unwrap();
        assert!(err.to_string().contains("ns2.ipssl.cc"), "{err}");

        // An address under [hosts] does as well.
        cfg.hosts.insert(
            "ns2".into(),
            HostConfig {
                aaaa: vec!["2001:db8::54".parse().unwrap()],
                ..HostConfig::default()
            },
        );
        let zone = Zone::from_config(&cfg).unwrap();
        assert_eq!(
            rdata(&query_zone(&zone, "ns2.ipssl.cc.", RecordType::AAAA)),
            ["2001:db8::54"]
        );
    }

    #[test]
    fn duplicate_records_are_served_once() {
        let zone = zone_with(
            "[hosts.ns1]\na = [\"198.51.100.1\", \"198.51.100.3\"]\n\
             [hosts.twice]\ntxt = [\"same\", \"same\"]",
        )
        .unwrap();
        assert_eq!(
            rdata(&query_zone(&zone, "ns1.ipssl.cc.", RecordType::A)),
            ["198.51.100.1", "198.51.100.3"]
        );
        assert_eq!(
            rdata(&query_zone(&zone, "twice.ipssl.cc.", RecordType::TXT)),
            ["same"]
        );
    }

    #[test]
    fn fixed_hosts() {
        assert_eq!(
            rdata(&query("www.ipssl.cc.", RecordType::A)),
            ["198.51.100.10"]
        );
        let dmarc = query("_dmarc.ipssl.cc.", RecordType::TXT);
        assert_eq!(rdata(&dmarc), ["v=DMARC1; p=reject"]);
        // A fixed name has only the records configured for it, plus the
        // address in its name, and `www` holds none.
        assert!(is_nodata(&query("www.ipssl.cc.", RecordType::AAAA)));
    }

    #[test]
    fn fixed_host_without_address_keeps_the_one_in_its_name() {
        let zone = zone_with(
            r#"
            [hosts."10-0-0-7"]
            txt = ["site-verification=1"]

            [hosts."10-0-0-8"]
            a = ["198.51.100.20"]

            [hosts."2001-db8--7"]
            txt = ["site-verification=2"]

            [hosts."empty-10-0-0-9"]

            [hosts."203-0-113-9"]
            txt = ["site-verification=3"]
            "#,
        )
        .unwrap();
        let q = |name: &str, qtype| query_zone(&zone, name, qtype);

        assert_eq!(rdata(&q("10-0-0-7.ipssl.cc.", RecordType::A)), ["10.0.0.7"]);
        assert_eq!(
            rdata(&q("10-0-0-7.ipssl.cc.", RecordType::TXT)),
            ["site-verification=1"]
        );
        // ANY still gets the first configured RRset.
        assert_eq!(
            q("10-0-0-7.ipssl.cc.", RecordType::ANY).answers[0].record_type(),
            RecordType::TXT
        );
        assert!(is_nodata(&q("10-0-0-7.ipssl.cc.", RecordType::AAAA)));
        assert_eq!(
            rdata(&q("2001-db8--7.ipssl.cc.", RecordType::AAAA)),
            ["2001:db8::7"]
        );
        assert_eq!(
            rdata(&q("empty-10-0-0-9.ipssl.cc.", RecordType::ANY)),
            ["10.0.0.9"]
        );

        // A configured address replaces the one in the name.
        assert_eq!(
            rdata(&q("10-0-0-8.ipssl.cc.", RecordType::A)),
            ["198.51.100.20"]
        );
        assert!(is_nodata(&q("10-0-0-8.ipssl.cc.", RecordType::AAAA)));

        // A blocked address stays unserved, but the name has records.
        assert!(is_nodata(&q("203-0-113-9.ipssl.cc.", RecordType::A)));
        assert_eq!(
            rdata(&q("203-0-113-9.ipssl.cc.", RecordType::TXT)),
            ["site-verification=3"]
        );
    }

    #[test]
    fn mx_records() {
        assert_eq!(
            rdata(&query("ipssl.cc.", RecordType::MX)),
            ["10 mx.example.net.", "20 mx2.example.net."]
        );
        // Names computed from an address have no MX.
        assert!(is_nodata(&query("10-0-0-1.ipssl.cc.", RecordType::MX)));
    }

    #[test]
    fn null_mx() {
        let zone =
            zone_with("[hosts.nomail]\nmx = [{ preference = 0, exchange = \".\" }]").unwrap();
        let a = query_zone(&zone, "nomail.ipssl.cc.", RecordType::MX);
        assert_eq!(rdata(&a), ["0 ."]);
    }

    #[test]
    fn rejects_bad_mx() {
        for mx in [
            r#"{ preference = 10, exchange = "." }"#,
            r#"{ preference = 10, exchange = "" }"#,
            r#"{ preference = 0, exchange = "." }, { preference = 10, exchange = "mx.example.net" }"#,
            r#"{ preference = 10, exchange = "192.0.2.25" }"#,
            r#"{ preference = 10, exchange = "192.0.2.15." }"#,
            r#"{ preference = 10, exchange = "2001:db8::25." }"#,
            r#"{ preference = 10, exchange = "mx\\.example.net" }"#,
        ] {
            let err = zone_with(&format!("[hosts.bad]\nmx = [{mx}]")).err();
            assert!(err.is_some(), "accepted {mx}");
        }
    }

    #[test]
    fn long_txt_is_split() {
        // An RSA DKIM key does not fit in one 255-byte string.
        let key = format!("v=DKIM1; k=rsa; p={}", "A".repeat(600));
        let zone = zone_with(&format!("[hosts.\"s1._domainkey\"]\ntxt = [\"{key}\"]")).unwrap();
        let a = query_zone(&zone, "s1._domainkey.ipssl.cc.", RecordType::TXT);
        let RData::TXT(txt) = &a.answers[0].data else {
            panic!("not a TXT record");
        };
        let lengths: Vec<usize> = txt.txt_data.iter().map(|s| s.len()).collect();
        assert_eq!(lengths, [255, 255, 108]);
        assert_eq!(txt.txt_data.concat(), key.as_bytes());
    }

    #[test]
    fn rejects_rrsets_too_big_for_a_message() {
        let txt = |count: usize| {
            let values: Vec<String> = (0..count)
                .map(|i| format!("\"{i:03}{}\"", "A".repeat(247)))
                .collect();
            format!("[hosts.big]\ntxt = [{}]", values.join(", "))
        };
        // Records that are fine on their own but too big together.
        let err = zone_with(&txt(300)).err().unwrap();
        assert!(err.to_string().contains("do not fit"), "{err}");
        // One record longer than RDATA can be.
        let huge = format!("[hosts.big]\ntxt = [\"{}\"]", "A".repeat(70_000));
        assert!(zone_with(&huge).is_err());
        // Big, but it fits.
        zone_with(&txt(200)).unwrap();
    }

    #[test]
    fn empty_non_terminal_is_nodata() {
        assert!(is_nodata(&query("nested.ipssl.cc.", RecordType::A)));
        assert_eq!(
            rdata(&query("deep.nested.ipssl.cc.", RecordType::A)),
            ["198.51.100.11"]
        );
    }

    #[test]
    fn whoami_returns_client_address() {
        let a = query("ip.ipssl.cc.", RecordType::TXT);
        assert_eq!(rdata(&a), ["192.0.2.99"]);
        assert_eq!(a.answers[0].ttl, 0);
    }

    #[test]
    fn blocklisted_address_is_nxdomain() {
        for (name, qtype) in [
            ("203-0-113-5.ipssl.cc.", RecordType::A),
            ("203.0.113.5.ipssl.cc.", RecordType::A),
            ("app.203-0-113-5.ipssl.cc.", RecordType::TXT),
            // ::ffff:203.0.113.5 is the same address.
            ("0--ffff-cb00-7105.ipssl.cc.", RecordType::AAAA),
        ] {
            let a = query(name, qtype);
            assert_eq!(a.rcode, ResponseCode::NXDomain, "{name}");
            assert!(a.authoritative && a.soa.is_some());
        }
    }

    #[test]
    fn blocked_names_above_fixed_hosts_exist() {
        let zone = zone_with("[hosts.\"www.203-0-113-6\"]\na = [\"198.51.100.30\"]").unwrap();
        let q = |name: &str| query_zone(&zone, name, RecordType::A);
        assert!(is_nodata(&q("203-0-113-6.ipssl.cc.")));
        assert_eq!(rdata(&q("www.203-0-113-6.ipssl.cc.")), ["198.51.100.30"]);
        assert_eq!(q("app.203-0-113-6.ipssl.cc.").rcode, ResponseCode::NXDomain);
    }

    #[test]
    fn non_in_class_is_refused() {
        let name = Name::from_ascii("10-0-0-1.ipssl.cc.").unwrap();
        let a = zone().resolve(&name, RecordType::A, DNSClass::CH, CLIENT);
        assert_eq!(a.rcode, ResponseCode::Refused);
    }

    #[test]
    fn rejects_out_of_zone_glue() {
        let cfg = CONFIG.replace("ns2.ipssl.cc", "ns.example.net");
        let err = Zone::from_config(&Config::parse(&cfg).unwrap())
            .err()
            .unwrap();
        assert!(err.to_string().contains("outside"), "{err}");
    }

    #[test]
    fn rejects_the_root_as_domain() {
        for domain in ["", "."] {
            let mut cfg = config();
            cfg.domain = domain.into();
            assert!(Zone::from_config(&cfg).is_err(), "{domain:?}");
        }
    }

    #[test]
    fn rejects_hosts_that_differ_only_in_case() {
        let err = zone_with(
            "[hosts.MailAlias]\nmx = [{ preference = 0, exchange = \".\" }]\n\
             [hosts.mailalias]\nmx = [{ preference = 20, exchange = \"mail.example.net\" }]",
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("same name"), "{err}");
    }

    #[test]
    fn rejects_wildcard_hosts() {
        for host in ["\"*\"", "\"*.dev\""] {
            let err = zone_with(&format!("[hosts.{host}]\na = [\"198.51.100.40\"]")).err();
            assert!(err.is_some(), "accepted {host}");
        }
    }

    #[test]
    fn rejects_backslashes_in_names() {
        // `\101` would be read as octal and publish `aast`.
        assert!(zone_with("[hosts.'\\101ast']\na = [\"198.51.100.40\"]").is_err());
        let mut cfg = config();
        cfg.domain = r"ipssl\.cc".into();
        assert!(Zone::from_config(&cfg).is_err());
        let mut cfg = config();
        cfg.nameservers[1].name = r"ns2\.ipssl.cc".into();
        assert!(Zone::from_config(&cfg).is_err());
    }

    #[test]
    fn rejects_out_of_range_timers() {
        let cases: [fn(&mut Config); 6] = [
            |c| c.ttl.ip = MAX_TTL + 1,
            |c| c.ttl.records = u32::MAX,
            |c| c.soa.minimum = MAX_TTL + 1,
            |c| c.soa.refresh = -1,
            |c| c.soa.retry = 0,
            |c| c.soa.expire = i32::MIN,
        ];
        for (i, set) in cases.iter().enumerate() {
            let mut cfg = config();
            set(&mut cfg);
            assert!(Zone::from_config(&cfg).is_err(), "case {i}");
        }

        // The largest values are fine.
        let mut cfg = config();
        cfg.ttl.ip = MAX_TTL;
        cfg.ttl.records = MAX_TTL;
        cfg.soa.minimum = MAX_TTL;
        cfg.soa.refresh = i32::MAX;
        cfg.soa.retry = i32::MAX;
        cfg.soa.expire = i32::MAX;
        Zone::from_config(&cfg).unwrap();
    }

    #[test]
    fn soa_email() {
        for email in [
            "ops@",
            "ops@.",
            "@ipssl.cc",
            "ops.dns@example.org",
            "hostmaster",
        ] {
            let mut cfg = config();
            cfg.soa.email = email.into();
            assert!(Zone::from_config(&cfg).is_err(), "accepted {email:?}");
        }
        let soa = query("ipssl.cc.", RecordType::SOA);
        let RData::SOA(soa) = &soa.answers[0].data else {
            panic!("not an SOA record");
        };
        assert_eq!(soa.rname.to_string(), "hostmaster.ipssl.cc.");
    }

    #[test]
    fn caa_issuers() {
        for issuer in [
            "ca_team.example",
            "-ca.example",
            "ca-.example",
            "ca..example",
            "ca example.org",
            "",
            ".",
        ] {
            let mut cfg = config();
            cfg.caa_issuers = vec![issuer.into()];
            assert!(Zone::from_config(&cfg).is_err(), "accepted {issuer:?}");
        }
        let mut cfg = config();
        cfg.caa_issuers = vec!["letsencrypt.org.".into(), "pki.goog".into()];
        let zone = Zone::from_config(&cfg).unwrap();
        assert_eq!(
            rdata(&query_zone(&zone, "ipssl.cc.", RecordType::CAA)),
            ["0 issue \"letsencrypt.org\"", "0 issue \"pki.goog\""]
        );
    }

    #[test]
    fn challenge_names() {
        let cfg = CONFIG.replace(
            r#"blocklist = ["203.0.113.0/24"]"#,
            r#"blocklist = ["203.0.113.0/24", "10.9.0.0/16"]"#,
        );
        let zone = Zone::from_config(&Config::parse(&cfg).unwrap()).unwrap();
        for ok in [
            "_acme-challenge.10-0-2-2.ipssl.cc",
            "_acme-challenge.10-0-2-2.ipssl.cc.",
            "_ACME-Challenge.App.192-168-1-10.IPSSL.cc",
            "_acme-challenge.fd00--1.ipssl.cc",
            "_acme-challenge.100-64-0-1.ipssl.cc",
        ] {
            assert!(zone.challenge_name(ok).is_ok(), "{ok}");
        }
        for (bad, why) in [
            ("", ChallengeError::Invalid),
            ("_acme-challenge..ipssl.cc", ChallengeError::Invalid),
            (
                "_acme-challenge.10-0-2-2.example.com",
                ChallengeError::OutsideZone,
            ),
            ("10-0-2-2.ipssl.cc", ChallengeError::NotChallenge),
            (
                "x._acme-challenge.10-0-2-2.ipssl.cc",
                ChallengeError::NotChallenge,
            ),
            ("_acme-challenge.ipssl.cc", ChallengeError::NoAddress),
            ("_acme-challenge.www.ipssl.cc", ChallengeError::NoAddress),
            (
                "_acme-challenge.198-51-100-10.ipssl.cc",
                ChallengeError::PublicAddress,
            ),
            (
                "_acme-challenge.203-0-113-10.ipssl.cc",
                ChallengeError::Blocked,
            ),
            (
                "_acme-challenge.2001-db8--1.ipssl.cc",
                ChallengeError::PublicAddress,
            ),
            ("_acme-challenge.10-9-1-1.ipssl.cc", ChallengeError::Blocked),
            // ::ffff:10.9.1.1, the same address as IPv4-mapped IPv6.
            (
                "_acme-challenge.0--ffff-a09-101.ipssl.cc",
                ChallengeError::Blocked,
            ),
        ] {
            assert_eq!(zone.challenge_name(bad).err(), Some(why), "{bad:?}");
        }
        // The name comes back normalized, so it can be used as a key.
        assert_eq!(
            zone.challenge_name("_ACME-challenge.10-0-2-2.ipssl.cc")
                .unwrap()
                .to_string(),
            "_acme-challenge.10-0-2-2.ipssl.cc."
        );
    }

    #[test]
    fn challenge_answers_never_cache() {
        let zone = zone();
        let name = Name::from_ascii("_acme-challenge.10-0-2-2.ipssl.cc.").unwrap();
        let a = zone.challenge_answer(&name, vec!["one".into(), "two".into()]);
        assert!(a.authoritative);
        assert_eq!(rdata(&a), ["one", "two"]);
        assert!(a.answers.iter().all(|r| r.ttl == 0));

        let empty = zone.challenge_answer(&name, vec![]);
        assert_eq!(empty.rcode, ResponseCode::NoError);
        assert!(empty.answers.is_empty());
        assert_eq!(empty.soa.unwrap().ttl, 0);
    }
}
