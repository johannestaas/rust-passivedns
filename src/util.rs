//! Utilities shared by parsers
//!
//! includes:
//!
//! parse_name_into(&[u8], &mut String)

use std::str::from_utf8;

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
            if i as usize >= data.len() {
                break;
            }
            s.push_str(from_utf8(&[data[i as usize]]).unwrap());
        }
        s.push('.');
        i += 1;
        if i as usize >= data.len() {
            break;
        }
    }
    return i;
}

pub fn vec2hex(v: &[u8]) -> String {
    let mut s = format!("{:02X}", &v[0]);;
    for i in &v[1..] {
        s = format!("{} {:02X}", s, i);
    }
    s
}

pub fn decompress_into(data: &[u8], i: u32, s: &mut String) {
    let mut ic: u32 = 0;
    'outer: loop {
        let l = data[(i + ic) as usize];
        println!("starting at {}, found: {:02X}", i + ic, l);
        if l & 0xc0 == 0xc0 {
            let next = to_ptr!(data, i + ic);
            let mut s2 = String::new();
            decompress_into(&data, next, &mut s2);
            s.push('.');
            s.push_str(s2.as_str());
            break 'outer;
        }
        ic += 1;
        for _ in 0..l {
            let index = (i + ic) as usize;
            let c = data[index];
            if c == 0x0 {
                break 'outer;
            } else {
                s.push(c as char);
            }
            ic += 1;
        }
        s.push('.');
    }
}
