//! 
//! http://www.networksorcery.com/enp/protocol/dns.htm
//!

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
pub struct DnsResponse {
    header: DnsHeader,
    questions: Vec<Query>,
    answer_rrs: Vec<ResourceRecord>,
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

    pub fn new(data: &[u8]) -> Option<DnsResponse> {
        if !DnsResponse::is_dns_response(data) {
            return None;
        }
        let hdr = DnsResponse::parse_header(&data[0x2a..0x36]);
        Some(DnsResponse {
            header: hdr,
            questions: Vec::new(),
            answer_rrs: Vec::new(),
        })
    }

    fn is_dns_response(data: &[u8]) -> bool {
        if data.len() < 0x24 {
            return false;
        }
        let src_port_bytes = &data[0x22..0x24];
        let src_port: u16 = (u16::from(src_port_bytes[0]) << 8) + u16::from(src_port_bytes[1]);
        if src_port != 53 {
            return false;
        }
        data[0x2c] == 0x81 && data[0x2d] == 0x80
    }

    fn dns_query(&self, data: &[u8]) -> String {
        let mut fqdn: String = String::new();
        let mut i: usize = 0x37;
        while data[i] != 0x0 {
            i += 1;
        }
        let query_bytes = &data[0x37..i];
        let query = std::str::from_utf8(query_bytes).unwrap();
        let split_3 = query.split("\x03");
        for slc in split_3 {
            fqdn.push_str(slc);
            fqdn.push('.');
        };
        fqdn
    }
}
