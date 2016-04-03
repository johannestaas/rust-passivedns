//! The DNS Class enum and implementation.
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum Class {
    RESERVED, IN, CH, HS, NONE, ANY, PRIVATE, OTHER, UNMAPPED
}

impl Class {
    /// Creates a Class from a u16, DnsType::UNMAPPED if not implemented yet
    pub fn new(i: u16) -> Class {
        match i {
            0 => Class::RESERVED,
            1 => Class::IN,
            3 => Class::CH,
            4 => Class::HS,
            254 => Class::NONE,
            255 => Class::ANY,
            65280...65534 => Class::PRIVATE,
            _ => Class::UNMAPPED,
        }
    }
}

impl fmt::Display for Class {
    /// Allows debug display of a Class
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            Class::RESERVED => "RESERVED",
            Class::IN => "IN",
            Class::CH => "CH",
            Class::HS => "HS",
            Class::NONE => "NONE",
            Class::ANY => "ANY",
            Class::PRIVATE => "PRIVATE",
            Class::UNMAPPED => "UNMAPPED",
            _ => "UNMAPPED",
        };
        write!(f, "{}", s)
    }
}


