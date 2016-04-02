//! The DNS Class enum and implementation.

#[derive(Debug)]
pub enum DnsClass {
    RESERVED, IN, CH, HS, NONE, ANY, PRIVATE, OTHER, UNMAPPED
}

