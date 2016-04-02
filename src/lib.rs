//! 
//! http://www.networksorcery.com/enp/protocol/dns.htm
//!

pub enum DnsType {
    A, NS, MD, MF, CNAME, SOA, MB, MG, MR, NULL, WKS, PTR, HINFO, MINFO, MX, 
    TXT, RP, AFSDB, X25, ISDN, RT, NSAP, NSAP_PTR, SIG, KEY, PX, GPOS, AAAA,
    LOC, NXT, EID, NIMLOC, SRV, ATMA, NAPTR, KX, CERT, A6, DNAME, SINK, OPT,
    APL, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM,
    TLSA, HIP, NINFO, RKEY, TALINK, CHILD_DS, SPF, UINFO, UID, GID, UNSPEC,
    TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ALL, URI, CAA, DNSSEC_TA,
    DNSSEC_LV, OTHER
}

pub enum DnsClass {
    RESERVED, IN, CH, HS, NONE, ANY, PRIVATE, OTHER
}

#[derive(Debug)]
pub struct Query {
    query_name: String,
    query_type: u16,
    query_class: u16,
}

#[derive(Debug)]
pub struct ResourceRecord {
    name: String,
    query_type: u16,
    query_class: u16,
    ttl: u32,
    rdata_length: u16,
    rdata: String,
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

macro_rules! gt0 {
    ($rshift: expr) => {
        if ($rshift) & 0x1 > 0 {true} else {false}
    }
}

impl DnsResponse {

    pub fn parse_header(data: &[u8]) -> DnsHeader {
        let ident: u16 = (u16::from(data[0]) << 8) | u16::from(data[1]);
        let data_0_16: u8 = data[2];
        let qr: bool = gt0!(data_0_16 >> 7);
        let op: u8 = (data_0_16 >> 3) & 0x0f;
        let aa: bool = gt0!(data_0_16 >> 2);
        let tc: bool = gt0!(data_0_16 >> 1);
        let rd: bool = gt0!(data_0_16 & 0x01);
        let data_16_32 = u8::from(data[3]);
        let ra: bool = gt0!(data_16_32 >> 7);
        let z: bool = gt0!(data_16_32 >> 6);
        let ad: bool = gt0!(data_16_32 >> 5);
        let cd: bool = gt0!(data_16_32 >> 4);
        let rcode: u8 = data_16_32 & 0x0f;
        let total_q: u16 = (u16::from(data[4]) << 8) | u16::from(data[5]);
        let total_answer_rrs: u16 = (u16::from(data[5]) << 8) | u16::from(data[6]);
        let total_auth_rrs: u16 = (u16::from(data[6]) << 8) | u16::from(data[7]);
        let total_add_rrs: u16 = (u16::from(data[7]) << 8) | u16::from(data[8]);
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

    pub fn parse_payload(data: &[u8]) -> DnsPayload {
        DnsPayload {
            questions: Vec::new(),
            answer_rrs: Vec::new(),
            authority_rrs: Vec::new(),
            additional_rrs: Vec::new(),
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
        let payload = DnsResponse::parse_payload(&data[0x36..]);
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
