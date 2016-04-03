//! Implements a Query struct and instanciates it from data.

use std::fmt;
use dnstype::Type; 
use dnsclass::Class;


/// The Query struct holds the name as a String
#[derive(Debug)]
pub struct Query {
    pub name: String,
    pub typ: Type,
    pub class: Class,
}

impl Query {
    pub fn new(s: String, data: &[u8], i: &mut u32) -> Query {
        let typ: u16 = to_u16!(data, 1);
        let class: u16 = to_u16!(data, 3);
        // After that is u16 name?
        *i += 5;
        Query {
            name: s,
            typ: Type::new(typ),
            class: Class::new(class),
        }
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{},{}", self.typ, self.name)
    }
}

