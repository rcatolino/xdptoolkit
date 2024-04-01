#![no_std]
#![no_main]

#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

use xdptoolkit::linux_net::xdp_action;
use xdptoolkit::debug::Printable;
use xdptoolkit::ip_parsing::IpParser;
use xdptoolkit::xdp::{Packet, XdpCtx};

#[inline(always)]
fn xdp_filter(ctx: XdpCtx) -> Option<()> {
    let p = Packet::new(ctx)?;
    let ip = p.filter_ip()?.filter_src(IpParser::new(b"0.0.0.0/0").parse())?;
    let tcp = ip.filter_tcp()?.filter_syn()?;
    tcp.bpf_printk();
    Some(())
}

#[no_mangle]
#[link_section = "xdp"]
pub fn xdp_main(ctx: XdpCtx) -> u32 {
    match xdp_filter(ctx) {
        Some(()) => xdp_action::XDP_PASS,
        None => xdp_action::XDP_PASS,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
