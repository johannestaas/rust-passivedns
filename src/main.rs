extern crate pcap;
extern crate passivedns;

use passivedns::dns::Response;
use passivedns::util::vec2hex;

fn device() -> pcap::Device {
    pcap::Device::lookup().unwrap()
}

fn capture(dev: pcap::Device) -> pcap::Capture<pcap::Active> {
    pcap::Capture::from_device(dev).unwrap().promisc(true).open().unwrap()
}

fn listen(cap: &mut pcap::Capture<pcap::Active>) {
    while let Ok(packet) = cap.next() {
        let response = match Response::new(&packet.data) {
            Some(response) => response,
            _ => continue,
        };
        //println!("{:?}", response);
        for rr in response.payload.answer_rrs {
            println!("{}", vec2hex(&rr.rdata));
            println!("{},{}", rr.name, rr.row());
        }
    }
}

fn main() {
    let dev = device();
    let mut cap = capture(dev);
    listen(&mut cap);
}
