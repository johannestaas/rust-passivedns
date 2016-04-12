//! ResourceRecord struct and implementation
//! Exists in DNS response payload.

use dnsclass::Class;
use dnstype::Type;
use util::decompress_into;

#[derive(Debug)]
pub struct ResourceRecord {
    pub name: u16,
    pub typ: Type,
    pub class: Class,
    pub ttl: u32,
    pub rdata_length: u16,
    pub rdata: Vec<u8>,
    rdata_start: u32,
}

impl ResourceRecord {
    /// Creates a ResourceRecord from a vector of u8 and mutable u32 index.
    pub fn new(data: &[u8], i: &mut u32) -> ResourceRecord {
        let name: u16 = to_u16!(data, *i as usize);
        *i += 2;
        let _typ: u16 = to_u16!(data, *i as usize);
        *i += 2;
        let _class: u16 = to_u16!(data, *i as usize);
        *i += 2;
        let ttl: u32 = to_u32!(data, *i as usize);
        *i += 4;
        let rlen: u16 = to_u16!(data, *i as usize);
        *i += 2;
        let rdata_start = *i;
        let mut rdata: Vec<u8> = Vec::new();
        rdata.extend((&data[*i as usize..rlen as usize + *i as usize]).iter().cloned());
        *i += rlen as u32;
        let typ = Type::new(_typ);
        let class = Class::new(_class);
        ResourceRecord {
            name: name,
            typ: typ,
            class: class,
            ttl: ttl,
            rdata_length: rlen,
            rdata: rdata,
            rdata_start: rdata_start,
        }
    }

    pub fn rdata(&self, data: &[u8]) -> String {
        match self.typ {
            Type::A => format!("{}.{}.{}.{}", self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3]),
            Type::MX => self.mx(data),
            Type::AAAA => format!("{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}:{:02X}{:02X}", self.rdata[0], self.rdata[1], self.rdata[2], self.rdata[3], self.rdata[4], self.rdata[5], self.rdata[6], self.rdata[7], self.rdata[8], self.rdata[9], self.rdata[10], self.rdata[11], self.rdata[12], self.rdata[13], self.rdata[14], self.rdata[15]),
            Type::CNAME => self.cname(data),
            _ => format!("{:?}", self.rdata),
        }
    }

    pub fn class(&self) -> String {
        format!("{}", self.class)
    }

    pub fn typ(&self) -> String {
        format!("{}", self.typ)
    }

    fn mx(&self, data: &[u8]) -> String {
        //let pref = to_u16!(&self.rdata, 0);
        let mut s: String = String::new();
        decompress_into(&data, self.rdata_start + 2, &mut s);
        s
    }

    fn cname(&self, data: &[u8]) -> String {
        let mut s: String = String::new();
        decompress_into(&data, self.rdata_start, &mut s);
        s
    }

    pub fn name(&self, data: &[u8]) -> String {
        let mut s = String::new();
        let ptr = u16_to_ptr!(self.name) - 12;
        decompress_into(&data, ptr, &mut s);
        s
    }
}
