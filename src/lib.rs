//! 
//! http://www.networksorcery.com/enp/protocol/dns.htm
//!
#![allow(non_camel_case_types)]

use std::fmt;
mod macros;
mod dnstype;
mod dnsclass;
mod rr;
mod query;

use rr::ResourceRecord;

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
