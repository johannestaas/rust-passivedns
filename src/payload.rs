//! DNS Payload struct and implementation

use header::Header;
use query::Query;
use rr::ResourceRecord;
//use dnstype::Type;
use util::{parse_name_into,vec2hex};

#[derive(Debug)]
pub struct Payload<'a> {
    pub questions: Vec<Query>,
    pub answer_rrs: Vec<ResourceRecord>,
    pub authority_rrs: Vec<ResourceRecord>,
    pub additional_rrs: Vec<ResourceRecord>,
    data: &'a[u8],
    end: u32,
}

impl<'a> Payload<'a> {
    pub fn new(hdr: &Header, data: &'a[u8]) -> Payload<'a> {
        let mut questions: Vec<Query> = Vec::new();
        let mut answer_rrs: Vec<ResourceRecord> = Vec::new();
        let mut authority_rrs: Vec<ResourceRecord> = Vec::new();
        let mut additional_rrs: Vec<ResourceRecord> = Vec::new();
        let mut i: u32 = 0;
        let mut name = String::new();

        for _ in 0..hdr.total_questions {
            i += parse_name_into(&data[(i as usize)..], &mut name);
            let q = Query::new(name.clone(), &data[(i as usize)..], &mut i);
            questions.push(q);
        }
        for _ in 0..hdr.total_answer_rrs {
            let rr = ResourceRecord::new(&data, &mut i);
            answer_rrs.push(rr);
        }
        for _ in 0..hdr.total_authority_rrs {
            let rr = ResourceRecord::new(&data, &mut i);
            authority_rrs.push(rr);
        }
        for _ in 0..hdr.total_additional_rrs {
            let rr = ResourceRecord::new(&data, &mut i);
            additional_rrs.push(rr);
        }
        Payload {
            questions: questions,
            answer_rrs: answer_rrs,
            authority_rrs: authority_rrs,
            additional_rrs: additional_rrs,
            data: data,
            end: i,
        }
    }

    pub fn records(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        for rr in &self.answer_rrs {
            println!("{}", vec2hex(&rr.rdata));
            let vs = format!("{},{},{},{},{}", rr.name(&self.data), rr.typ(), rr.class(), rr.ttl, rr.rdata(&self.data));
            v.push(vs);
        }
        v
    }
}
