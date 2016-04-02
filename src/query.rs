//! Implements a Query struct and instanciates it from data.

use std::fmt;
use dnstype::DnsType; 
use dnsclass::DnsClass;


/// The Query struct holds the name as a String
#[derive(Debug)]
pub struct Query {
    name: String,
    typ: u16,
    class: u16,
}

impl Query {
    pub fn new(s: String, data: &[u8], i: &mut u32) -> Query {
        let typ: u16 = to_u16!(data, 1);
        let class: u16 = to_u16!(data, 3);
        // After that is u16 name?
        *i += 5;
        Query {
            name: s,
            typ: typ,
            class: class,
        }
    }

    /// Gets a DnsType from its integer typ field.
    pub fn typ(&self) -> DnsType {
        match self.typ {
            1 => DnsType::A,
            2 => DnsType::NS,
            5 => DnsType::CNAME,
            12 => DnsType::PTR,
            15 => DnsType::MX,
            16 => DnsType::TXT,
            24 => DnsType::SIG,
            25 => DnsType::KEY,
            28 => DnsType::AAAA,
            29 => DnsType::LOC,
            33 => DnsType::SRV,
            37 => DnsType::CERT,
            39 => DnsType::DNAME,
            48 => DnsType::DNSKEY,
            249 => DnsType::TKEY,
            250 => DnsType::TSIG,
            251 => DnsType::IXFR,
            252 => DnsType::AXFR,
            32768 => DnsType::DNSSEC_TA,
            32769 => DnsType::DNSSEC_LV,
            _ => DnsType::UNMAPPED,
        }
    }

    pub fn class(&self) -> DnsClass {
        match self.class {
            0 => DnsClass::RESERVED,
            1 => DnsClass::IN,
            2 => DnsClass::OTHER,
            3 => DnsClass::CH,
            4 => DnsClass::HS,
            5...253 => DnsClass::OTHER,
            254 => DnsClass::NONE,
            255 => DnsClass::ANY,
            256...65279 => DnsClass::OTHER,
            65280...65534 => DnsClass::PRIVATE,
            65535 => DnsClass::OTHER,
            _ => DnsClass::UNMAPPED,
        }
    }

}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}] {}", self.typ(), self.name)
    }
}

