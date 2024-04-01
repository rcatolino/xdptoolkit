// Linux network struct bindings
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(unused)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub enum IpHdr {
    Ipv4(&'static ipv4hdr),
    Ipv6(&'static ipv6hdr),
}

#[derive(Debug,PartialEq)]
pub struct Ipv4Net {
    pub(crate) net: [u8; 4],
    pub(crate) mask: u8,
}

#[derive(Debug,PartialEq)]
pub struct Ipv6Net {
    net: [u8; 16],
    mask: u8,
}

#[derive(Debug,PartialEq)]
pub enum IpNet {
    v4(Ipv4Net),
    v6(Ipv6Net),
}

impl IpNet {
    pub fn new6(net: [u8; 16], mask: u8) -> Self {
        assert!(mask <= 128);
        Self::v6(Ipv6Net {
            net,
            mask,
        })
    }

    pub fn new4(net: [u8; 4], mask: u8) -> Self {
        assert!(mask <= 32);
        Self::v4(Ipv4Net {
            net,
            mask,
        })
    }
}


