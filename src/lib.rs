//! 
//! http://www.networksorcery.com/enp/protocol/dns.htm
//!
#![allow(non_camel_case_types)]

use std::fmt;
mod macros;

pub fn parse_name_into(data: &[u8], s: &mut String) -> u32 {
    let mut i: u32 = 0;
    if data.len() == 0 {
        return 0;
    }
    loop {
        let lbl_len = data[i as usize] as u32;
        if lbl_len == 0x0 {
            break;
        }
        for _ in 0..lbl_len {
            i += 1;
            s.push_str(std::str::from_utf8(&[data[i as usize]]).unwrap());
        }
        s.push('.');
        i += 1;
    }
    return i;
}

pub enum DnsType {
    ZERO, A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, 
    TXT, RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, KEY, PX, GPOS, AAAA,
    LOC, NXT, EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT,
    APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM,
    TLSA, HIP, NINFO, RKEY, TALINK, CHILD_DS, SPF, UINFO, UID, GID, UNSPEC,
    TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ALL, URI, CAA, DNSSEC_TA,
    DNSSEC_LV, OTHER, UNMAPPED
}

impl fmt::Display for DnsType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match *self {
            DnsType::A => "A",
            DnsType::NS => "NS",
            DnsType::CNAME => "CNAME",
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

#[derive(Debug)]
pub enum DnsClass {
    RESERVED, IN, CH, HS, NONE, ANY, PRIVATE, OTHER, UNMAPPED
}

#[derive(Debug)]
pub struct Query {
    name: String,
    typ: u16,
    class: u16,
}

#[derive(Debug)]
pub struct ResourceRecord {
    typ: u16,
    class: u16,
    ttl: u32,
    rdata_length: u16,
    rdata: Vec<u8>,
}

impl ResourceRecord {
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
            typ: typ,
            class: class,
            ttl: ttl,
            rdata_length: rlen,
            rdata: rdata,
        }
    }
}

#[derive(Debug)]
pub struct DnsHeader {
    identification: u16,
    qr: bool,
    opcode: u8,
    authoritative_answer: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    z: bool,
    authenticated_data: bool,
    checking_disabled: bool,
    return_code: u8,
    total_questions: u16,
    total_answer_rrs: u16,
    total_authority_rrs: u16,
    total_additional_rrs: u16,
}

#[derive(Debug)]
pub struct DnsPayload {
    questions: Vec<Query>,
    answer_rrs: Vec<ResourceRecord>,
    authority_rrs: Vec<ResourceRecord>,
    additional_rrs: Vec<ResourceRecord>,
}

#[derive(Debug)]
pub struct DnsResponse {
    header: DnsHeader,
    payload: DnsPayload,
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

impl DnsResponse {

    pub fn parse_header(data: &[u8]) -> DnsHeader {
        let ident: u16 = to_u16!(data, 0);
        let data_0_16: u8 = data[2];
        let qr: bool = gt0!(data_0_16 >> 7);
        let op: u8 = (data_0_16 >> 3) & 0x0f;
        let aa: bool = gt0!(data_0_16 >> 2);
        let tc: bool = gt0!(data_0_16 >> 1);
        let rd: bool = gt0!(data_0_16 & 0x01);
        let data_16_32: u8 = data[3];
        let ra: bool = gt0!(data_16_32 >> 7);
        let z: bool = gt0!(data_16_32 >> 6);
        let ad: bool = gt0!(data_16_32 >> 5);
        let cd: bool = gt0!(data_16_32 >> 4);
        let rcode: u8 = data_16_32 & 0x0f;
        let total_q: u16 = to_u16!(data, 4);
        let total_answer_rrs: u16 = to_u16!(data, 6);
        let total_auth_rrs: u16 = to_u16!(data, 8);
        let total_add_rrs: u16 = to_u16!(data, 10);
        DnsHeader {
            identification: ident,
            qr: qr,
            opcode: op,
            authoritative_answer: aa,
            truncated: tc,
            recursion_desired: rd,
            recursion_available: ra,
            z: z,
            authenticated_data: ad,
            checking_disabled: cd,
            return_code: rcode,
            total_questions: total_q,
            total_answer_rrs: total_answer_rrs,
            total_authority_rrs: total_auth_rrs,
            total_additional_rrs: total_add_rrs,
        }
    }

    pub fn parse_payload(hdr: &DnsHeader, data: &[u8]) -> DnsPayload {
        let mut questions: Vec<Query> = Vec::new();
        let mut answer_rrs: Vec<ResourceRecord> = Vec::new();
        let mut authority_rrs: Vec<ResourceRecord> = Vec::new();
        let mut additional_rrs: Vec<ResourceRecord> = Vec::new();
        let mut i: u32 = 0;

        for _ in 0..hdr.total_questions {
            let mut name = String::new();
            i += parse_name_into(&data[(i as usize)..], &mut name);
            let q = Query::new(name, &data[(i as usize)..], &mut i);
            questions.push(q);
        }
        for _ in 0..hdr.total_answer_rrs {
            let rr = ResourceRecord::new(&data, &mut i);
            answer_rrs.push(rr);
        }
        for _ in 0..hdr.total_authority_rrs {
            let rr = ResourceRecord::new(&data[..], &mut i);
            authority_rrs.push(rr);
        }
        for _ in 0..hdr.total_additional_rrs {
            let rr = ResourceRecord::new(&data[..], &mut i);
            additional_rrs.push(rr);
        }
        DnsPayload {
            questions: questions,
            answer_rrs: answer_rrs,
            authority_rrs: authority_rrs,
            additional_rrs: additional_rrs,
        }
    }

    pub fn new(data: &[u8]) -> Option<DnsResponse> {
        if data.len() < 0x36 {
            return None;
        }
        // if not port 53
        if !DnsResponse::is_port_53(data) {
            return None;
        }
        let hdr = DnsResponse::parse_header(&data[0x2a..0x36]);
        // if question_response is not a response
        if !hdr.qr {
            return None;
        }
        let payload = DnsResponse::parse_payload(&hdr, &data[0x36..]);
        Some(DnsResponse {
            header: hdr,
            payload: payload,
        })
    }

    fn is_port_53(data: &[u8]) -> bool {
        let src_port_bytes = &data[0x22..0x24];
        let src_port: u16 = (u16::from(src_port_bytes[0]) << 8) + u16::from(src_port_bytes[1]);
        src_port == 53
    }
}
