//! The DNS Class enum and implementation.
use std::fmt;

#[derive(Debug)]
pub enum DnsClass {
    RESERVED, IN, CH, HS, NONE, ANY, PRIVATE, OTHER, UNMAPPED
}

impl DnsClass {
    /// Creates a DnsClass from a u16, DnsType::UNMAPPED if not implemented yet
    pub fn new(i: u16) -> DnsClass {
        match i {
            0 => DnsClass::RESERVED,
            1 => DnsClass::IN,
            3 => DnsClass::CH,
            4 => DnsClass::HS,
            254 => DnsClass::NONE,
            255 => DnsClass::ANY,
            65280...65534 => DnsClass::PRIVATE,
            _ => DnsClass::UNMAPPED,
        }
    }
}

impl fmt::Display for DnsClass {
    /// Allows debug display of a DnsClass
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            DnsClass::RESERVED => "RESERVED",
            DnsClass::IN => "IN",
            DnsClass::CH => "CH",
            DnsClass::HS => "HS",
            DnsClass::NONE => "NONE",
            DnsClass::ANY => "ANY",
            DnsClass::PRIVATE => "PRIVATE",
            DnsClass::UNMAPPED => "UNMAPPED",
            _ => "UNMAPPED",
        };
        write!(f, "{}", s)
    }
}


