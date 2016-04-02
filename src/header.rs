//! DNS Header struct and implementation

#[derive(Debug)]
pub struct Header {
    pub identification: u16,
    pub qr: bool,
    pub opcode: u8,
    pub authoritative_answer: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub z: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub return_code: u8,
    pub total_questions: u16,
    pub total_answer_rrs: u16,
    pub total_authority_rrs: u16,
    pub total_additional_rrs: u16,
}

impl Header {
    pub fn new(data: &[u8]) -> Header {
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
        Header {
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
}
