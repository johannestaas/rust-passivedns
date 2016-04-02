//! Specifies DNS type information (A, CNAME, ...)
use std::fmt;

/// Enum of the different types (A, CNAME, ...)
pub enum DnsType {
    ZERO, A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, 
    TXT, RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, KEY, PX, GPOS, AAAA,
    LOC, NXT, EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT,
    APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM,
    TLSA, HIP, NINFO, RKEY, TALINK, CHILD_DS, SPF, UINFO, UID, GID, UNSPEC,
    TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ALL, URI, CAA, DNSSEC_TA,
    DNSSEC_LV, OTHER, UNMAPPED
}

impl DnsType {
    /// Creates a DnsType from u16, DnsType::UNMAPPED if not implemented yet
    pub fn new(i: u16) -> DnsType {
        match i {
            1 => DnsType::A,
            2 => DnsType::NS,
            5 => DnsType::CNAME,
            6 => DnsType::SOA,
            12 => DnsType::PTR,
            15 => DnsType::MX,
            16 => DnsType::TXT,
            28 => DnsType::AAAA,
            29 => DnsType::LOC,
            251 => DnsType::IXFR,
            252 => DnsType::AXFR,
            _ => DnsType::UNMAPPED,
        }
    }
}

impl fmt::Display for DnsType {
    /// Allows debug display of a DnsType, DnsType::A => "A", etc.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            DnsType::A => "A",
            DnsType::NS => "NS",
            DnsType::CNAME => "CNAME",
            DnsType::SOA => "SOA",
            DnsType::PTR => "PTR",
            DnsType::MX => "MX",
            DnsType::TXT => "TXT",
            DnsType::SIG => "SIG",
            DnsType::KEY => "KEY",
            DnsType::AAAA => "AAAA",
            DnsType::LOC => "LOC",
            DnsType::SRV => "SRV",
            DnsType::CERT => "CERT",
            DnsType::DNAME => "DNAME",
            DnsType::DNSKEY => "DNSKEY",
            DnsType::TKEY => "TKEY",
            DnsType::TSIG => "TSIG",
            DnsType::IXFR => "IXFR",
            DnsType::AXFR => "AXFR",
            DnsType::DNSSEC_TA => "DNSSEC_TA",
            DnsType::DNSSEC_LV => "DNSSEC_LV",
            DnsType::UNMAPPED => "UNMAPPED",
            _ => "UNMAPPED",
        };
        write!(f, "{}", s)
    }
}


