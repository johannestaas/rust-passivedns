extern crate pcap;

fn device() -> pcap::Device {
    pcap::Device::lookup().unwrap()
}

fn capture(dev: pcap::Device) -> pcap::Capture<pcap::Active> {
    pcap::Capture::from_device(dev).unwrap().promisc(true).open().unwrap()
}

fn is_dns_answer(data: &[u8]) -> bool {
    let src_port_bytes = &data[0x22..0x24];
    let src_port: u16 = (u16::from(src_port_bytes[0]) << 8) + u16::from(src_port_bytes[1]);
    if src_port != 53 {
        return false;
    }
    data[0x2c] == 0x81 && data[0x2d] == 0x80
}

fn dns_query(data: &[u8]) -> String {
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


fn listen(cap: &mut pcap::Capture<pcap::Active>) {
    while let Ok(packet) = cap.next() {
        if packet.header.len < 0x28 {
            continue;
        }
        // println!("src: {:?} dest: {:?}", src_port, dest_port);
        if is_dns_answer(&packet.data) {
            println!("received DNS answer: {:?}", packet);
            let query = dns_query(&packet.data);
            println!("queried: {}", query);
        }
    }
}

fn main() {
    let dev = device();
    let mut cap = capture(dev);
    listen(&mut cap);
}
