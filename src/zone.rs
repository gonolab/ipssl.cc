//! Answers queries for the zone. Pure logic with no I/O, so it is easy to test.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context, Result, ensure};
use hickory_server::proto::op::ResponseCode;
use hickory_server::proto::rr::rdata::{A, AAAA, CAA, MX, NS, SOA, TXT};
use hickory_server::proto::rr::{DNSClass, LowerName, Name, RData, Record, RecordType};
use ipnet::IpNet;

use crate::acme::{CHALLENGE_LABEL, is_private};
use crate::config::Config;
use crate::parse::extract_ip;

/// `ip.<domain>` answers TXT queries with the address of whoever asked
/// (usually the user's recursive resolver). Handy for debugging.
const WHOAMI_LABEL: &str = "ip";

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
    whoami: LowerName,
    ip_ttl: u32,
    blocklist: Vec<IpNet>,
    serial: u32,
}

impl Zone {
    pub fn from_config(cfg: &Config) -> Result<Self> {
        let origin = fqdn(&cfg.domain).context("invalid `domain`")?;
        ensure!(
            !cfg.nameservers.is_empty(),
            "at least one entry in `nameservers` is required"
        );
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
            let mut name = Name::from_ascii(issuer)
                .with_context(|| format!("invalid CAA issuer {issuer:?}"))?;
            name.set_fqdn(false);
            let caa = CAA::new_issue(false, Some(name), vec![]);
            apex.push(Record::from_rdata(origin.clone(), ttl, RData::CAA(caa)));
        }

        // Addresses for in-zone name servers.
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
        }

        // Fixed hosts from the config.
        for (label, host) in &cfg.hosts {
            let name = if label == "@" {
                origin.clone()
            } else {
                fqdn(&format!("{label}.{}", cfg.domain.trim_end_matches('.')))
                    .with_context(|| format!("invalid host {label:?}"))?
            };
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
            let null_mx = host.mx.iter().any(|mx| mx.exchange.trim() == ".");
            ensure!(
                !null_mx || (host.mx.len() == 1 && host.mx[0].preference == 0),
                "host {label:?}: a null MX (exchange \".\") must be the only MX and have preference 0"
            );
            for mx in &host.mx {
                ensure!(
                    mx.exchange.parse::<IpAddr>().is_err(),
                    "host {label:?}: MX exchange must be a host name, not an address: {}",
                    mx.exchange
                );
                let exchange = fqdn(&mx.exchange)
                    .with_context(|| format!("host {label:?}: invalid MX exchange"))?;
                let data = RData::MX(MX::new(mx.preference, exchange));
                records.push(Record::from_rdata(name.clone(), ttl, data));
            }
        }

        let whoami = fqdn(&format!(
            "{WHOAMI_LABEL}.{}",
            cfg.domain.trim_end_matches('.')
        ))?;

        Ok(Self {
            origin_labels: origin.num_labels() as usize,
            origin: LowerName::new(&origin),
            negative_soa,
            hosts,
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

        let labels = self.relative_labels(qname);
        let labels: Vec<&str> = labels.iter().map(String::as_str).collect();

        match extract_ip(&labels) {
            Some(ip) if self.blocklist.iter().any(|net| net.contains(&ip)) => self.nxdomain(),
            Some(IpAddr::V4(ip)) if matches!(qtype, RecordType::A | RecordType::ANY) => self
                .answer(vec![Record::from_rdata(
                    qname.clone(),
                    self.ip_ttl,
                    RData::A(A(ip)),
                )]),
            Some(IpAddr::V6(ip)) if matches!(qtype, RecordType::AAAA | RecordType::ANY) => self
                .answer(vec![Record::from_rdata(
                    qname.clone(),
                    self.ip_ttl,
                    RData::AAAA(AAAA(ip)),
                )]),
            Some(_) => self.nodata(),
            // A name that only exists as the parent of a fixed host.
            None if self.hosts.keys().any(|k| lower.zone_of(k)) => self.nodata(),
            None => self.nxdomain(),
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
                if self.blocklist.iter().any(|net| net.contains(&ip)) {
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
        let relative = name.num_labels() as usize - self.origin_labels;
        name.iter()
            .take(relative)
            .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
            .collect()
    }

    fn fixed(&self, qname: &Name, records: &[Record], qtype: RecordType) -> Answer {
        // RFC 8482: answer ANY with one RRset instead of everything.
        let wanted = match qtype {
            RecordType::ANY => match records.first() {
                Some(r) => r.record_type(),
                None => return self.nodata(),
            },
            t => t,
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
        if matched.is_empty() {
            self.nodata()
        } else {
            self.answer(matched)
        }
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

/// Parses `name` as a fully qualified domain name.
fn fqdn(name: &str) -> Result<Name> {
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
    fqdn(&format!("{local}.{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn zone() -> Zone {
        Zone::from_config(&Config::parse(CONFIG).unwrap()).unwrap()
    }

    fn query(name: &str, qtype: RecordType) -> Answer {
        let name = Name::from_ascii(name).unwrap();
        zone().resolve(&name, qtype, DNSClass::IN, CLIENT)
    }

    fn rdata(answer: &Answer) -> Vec<String> {
        answer.answers.iter().map(|r| r.data.to_string()).collect()
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
            let a = query(name, qtype);
            assert_eq!(a.rcode, ResponseCode::NoError, "{name} {qtype}");
            assert!(a.answers.is_empty());
            assert!(a.soa.is_some());
        }
    }

    #[test]
    fn unknown_name_is_nxdomain() {
        let a = query("nothing-here.ipssl.cc.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::NXDomain);
        assert!(a.authoritative);
        assert_eq!(a.soa.unwrap().ttl, 300);
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
    fn case_is_ignored_and_preserved() {
        let a = query("App-10-0-0-1.IPSSL.cc.", RecordType::A);
        assert_eq!(rdata(&a), ["10.0.0.1"]);
        assert_eq!(a.answers[0].name.to_string(), "App-10-0-0-1.IPSSL.cc.");
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
    fn fixed_hosts() {
        assert_eq!(
            rdata(&query("www.ipssl.cc.", RecordType::A)),
            ["198.51.100.10"]
        );
        let dmarc = query("_dmarc.ipssl.cc.", RecordType::TXT);
        assert_eq!(rdata(&dmarc), ["v=DMARC1; p=reject"]);
        // A fixed name has only the records configured for it.
        let a = query("www.ipssl.cc.", RecordType::AAAA);
        assert_eq!(a.rcode, ResponseCode::NoError);
        assert!(a.answers.is_empty());
    }

    fn zone_with(extra: &str) -> Result<Zone> {
        Zone::from_config(&Config::parse(&format!("{CONFIG}\n{extra}\n")).unwrap())
    }

    #[test]
    fn mx_records() {
        assert_eq!(
            rdata(&query("ipssl.cc.", RecordType::MX)),
            ["10 mx.example.net.", "20 mx2.example.net."]
        );
        // Names computed from an address have no MX.
        let a = query("10-0-0-1.ipssl.cc.", RecordType::MX);
        assert_eq!(a.rcode, ResponseCode::NoError);
        assert!(a.answers.is_empty());
    }

    #[test]
    fn null_mx() {
        let zone =
            zone_with("[hosts.nomail]\nmx = [{ preference = 0, exchange = \".\" }]").unwrap();
        let name = Name::from_ascii("nomail.ipssl.cc.").unwrap();
        let a = zone.resolve(&name, RecordType::MX, DNSClass::IN, CLIENT);
        assert_eq!(rdata(&a), ["0 ."]);
    }

    #[test]
    fn rejects_bad_mx() {
        for mx in [
            r#"{ preference = 10, exchange = "." }"#,
            r#"{ preference = 0, exchange = "." }, { preference = 10, exchange = "mx.example.net" }"#,
            r#"{ preference = 10, exchange = "192.0.2.25" }"#,
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
        let name = Name::from_ascii("s1._domainkey.ipssl.cc.").unwrap();
        let a = zone.resolve(&name, RecordType::TXT, DNSClass::IN, CLIENT);
        let RData::TXT(txt) = &a.answers[0].data else {
            panic!("not a TXT record");
        };
        let lengths: Vec<usize> = txt.txt_data.iter().map(|s| s.len()).collect();
        assert_eq!(lengths, [255, 255, 108]);
        assert_eq!(txt.txt_data.concat(), key.as_bytes());
    }

    #[test]
    fn empty_non_terminal_is_nodata() {
        let a = query("nested.ipssl.cc.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::NoError);
        assert!(a.answers.is_empty());
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
        let a = query("203-0-113-5.ipssl.cc.", RecordType::A);
        assert_eq!(a.rcode, ResponseCode::NXDomain);
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
