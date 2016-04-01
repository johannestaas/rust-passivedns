extern crate pcap;

fn device() -> pcap::Device {
    pcap::Device::lookup().unwrap()
}

fn capture(dev: pcap::Device) -> pcap::Capture<pcap::Active> {
    pcap::Capture::from_device(dev).unwrap().promisc(true).open().unwrap()
}

fn main() {
    let dev = device();
    let mut cap = capture(dev);
    while let Ok(packet) = cap.next() {
        println!("received packet: {:?}", packet);
    }
}
