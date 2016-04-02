//! Specifies DNS type information (A, CNAME, ...)
use std::fmt;

/// Enum of the different types (A, CNAME, ...)
#[derive(Debug)]
pub enum Type {
    ZERO, A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, 
    TXT, RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, KEY, PX, GPOS, AAAA,
    LOC, NXT, EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT,
    APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM,
    TLSA, HIP, NINFO, RKEY, TALINK, CHILD_DS, SPF, UINFO, UID, GID, UNSPEC,
    TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ALL, URI, CAA, DNSSEC_TA,
    DNSSEC_LV, OTHER, UNMAPPED
}

impl Type {
    /// Creates a Type from u16, Type::UNMAPPED if not implemented yet
    pub fn new(i: u16) -> Type {
        match i {
            1 => Type::A,
            2 => Type::NS,
            5 => Type::CNAME,
            6 => Type::SOA,
            12 => Type::PTR,
            15 => Type::MX,
            16 => Type::TXT,
            28 => Type::AAAA,
            29 => Type::LOC,
            251 => Type::IXFR,
            252 => Type::AXFR,
            _ => Type::UNMAPPED,
        }
    }
}

impl fmt::Display for Type {
    /// Allows debug display of a Type, Type::A => "A", etc.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            Type::A => "A",
            Type::NS => "NS",
            Type::CNAME => "CNAME",
            Type::SOA => "SOA",
            Type::PTR => "PTR",
            Type::MX => "MX",
            Type::TXT => "TXT",
            Type::SIG => "SIG",
            Type::KEY => "KEY",
            Type::AAAA => "AAAA",
            Type::LOC => "LOC",
            Type::SRV => "SRV",
            Type::CERT => "CERT",
            Type::DNAME => "DNAME",
            Type::DNSKEY => "DNSKEY",
            Type::TKEY => "TKEY",
            Type::TSIG => "TSIG",
            Type::IXFR => "IXFR",
            Type::AXFR => "AXFR",
            Type::DNSSEC_TA => "DNSSEC_TA",
            Type::DNSSEC_LV => "DNSSEC_LV",
            Type::UNMAPPED => "UNMAPPED",
            _ => "UNMAPPED",
        };
        write!(f, "{}", s)
    }
}


