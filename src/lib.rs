//! 
//! http://www.networksorcery.com/enp/protocol/dns.htm
//!

pub struct Query {
    query_name: String,
    query_type: u16,
    query_class: u16,
}

pub struct ResourceRecord {
    name: String,
    query_type: u16,
    query_class: u16,
    ttl: u32,
    rdata_length: u16,
    rdata: String,
}

pub struct DnsResponse {
    total_questions: u16,
    total_answer_rrs: u16,
    total_authority_rrs: u16,
    total_additional_rrs: u16,
    questions: Vec<Query>,
    answer_rrs: Vec<ResourceRecord>,
}

impl DnsResponse {

    pub fn new(data: &[u8]) -> Option<DnsResponse> {
        if !DnsResponse::is_dns_response(data) {
            return None;
        }
        Some(DnsResponse {
            total_questions: 0,
            total_answer_rrs: 0,
            total_authority_rrs: 0,
            total_additional_rrs: 0,
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
