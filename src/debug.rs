use core::{ffi, mem};

use crate::{
    linux_net::{ipv4hdr, ipv6hdr, tcphdr, IpHdr},
    xdp::TcpPacket,
};

pub trait Printable {
    fn bpf_printk(&self);
}

pub unsafe fn bpf_vprintk(msg: &[u8]) {
    let vprintk: unsafe extern "C" fn(
        fmt: *const u8,
        fmt_size: u32,
        data: *const ffi::c_void,
        data_len: u32,
    ) -> ffi::c_long = mem::transmute(177usize);

    vprintk(msg.as_ptr(), msg.len().try_into().unwrap(), [].as_ptr(), 0);
}

impl Printable for tcphdr {
    fn bpf_printk(&self) {
        let syn = if self.syn() == 1 { 'S' } else { '-' };
        let ack = if self.ack() == 1 { 'A' } else { '-' };
        let psh = if self.psh() == 1 { 'P' } else { '-' };
        let fin = if self.fin() == 1 { 'F' } else { '-' };
        let rst = if self.rst() == 1 { 'R' } else { '-' };

        unsafe {
            bpf_vprintk(b"coucou tcphdr");
            /*
            bpf_trace_printk(
                b"TCP %d -> %d [%c%c%c%c%c]",
                u16::from_be(self.source),
                u16::from_be(self.dest),
                syn,
                ack,
                psh,
                fin,
                rst,
            );
            */
        }
    }
}

impl Printable for IpHdr {
    fn bpf_printk(&self) {
        match self {
            Self::Ipv4(inner) => inner.bpf_printk(),
            Self::Ipv6(inner) => inner.bpf_printk(),
        }
    }
}

impl Printable for ipv6hdr {
    fn bpf_printk(&self) {
        unsafe {
            bpf_vprintk(b"coucou ipv6hdr");
            /*
            bpf_trace_printk(
                b"ipv6/%x %pI6c -> %pI6c %d",
                self.nexthdr,
                &self.saddr as *const u8,
                &self.daddr as *const u8,
                u16::from_be(self.payload_len),
            )
            */
        };
    }
}

impl Printable for ipv4hdr {
    fn bpf_printk(&self) {
        unsafe {
            bpf_vprintk(b"coucou ipv4hdr");
            /*
            bpf_trace_printk(
                b"ipv4/%d %pI4 -> %pI4 %d",
                self.protocol,
                &self.saddr as *const u8,
                &self.daddr as *const u8,
                u16::from_be(self.tot_len),
            )
            */
        };

        /*
        unsafe { bpf_printk!(b"ipv4/%d %d.%d.%d.%d -> %d.%d.%d.%d %d",
                             self.protocol,
                             self.saddr[0], self.saddr[1], self.saddr[2], self.saddr[3],
                             self.daddr[0], self.daddr[1], self.daddr[2], self.daddr[3],
                             u16::from_be(self.tot_len)) };
                             */
    }
}

impl Printable for TcpPacket {
    fn bpf_printk(&self) {
        self.hdr.bpf_printk()
    }
}
