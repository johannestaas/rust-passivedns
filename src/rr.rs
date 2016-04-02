//! ResourceRecord struct and implementation
//! Exists in DNS response payload.

use dnsclass::Class;
use dnstype::Type;

#[derive(Debug)]
pub struct ResourceRecord {
    typ: Type,
    class: Class,
    ttl: u32,
    rdata_length: u16,
    rdata: Vec<u8>,
}

impl ResourceRecord {
    /// Creates a ResourceRecord from a vector of u8 and mutable u32 index.
    pub fn new(data: &[u8], i: &mut u32) -> ResourceRecord {
        //let unknown: u16 = to_u16!(data, 0);
        *i += 2;
        let typ: u16 = to_u16!(data, *i as usize);
        *i += 2;
        let class: u16 = to_u16!(data, *i as usize);
        *i += 2;
        let ttl: u32 = to_u32!(data, *i as usize);
        *i += 4;
        let rlen: u16 = to_u16!(data, *i as usize);
        *i += 2;
        let mut rdata: Vec<u8> = Vec::new();
        rdata.extend((&data[*i as usize..rlen as usize + *i as usize]).iter().cloned());
        *i += rlen as u32;
        ResourceRecord {
            typ: Type::new(typ),
            class: Class::new(class),
            ttl: ttl,
            rdata_length: rlen,
            rdata: rdata,
        }
    }

    pub fn serialize(&self) -> String {
        match self.typ {
            Type::A => "A".to_string(),
            _ => "UNMAPPED".to_string(),
        }
    }
}
