// XDP parsing helpers

use core::mem;

use crate::debug::bpf_vprintk;
use crate::linux_net;
use crate::linux_net::{ethhdr, ipv4hdr, ipv6hdr, tcphdr, xdp_md, IpHdr, IpNet};

pub type XdpCtx = *mut xdp_md;

pub trait Xdp {
    fn data(self) -> usize;
    fn data_end(self) -> usize;
    fn data_meta(self) -> usize;
}

impl Xdp for XdpCtx {
    fn data(self) -> usize {
        unsafe { (*self).data as usize}
    }
    fn data_end(self) -> usize {
        unsafe { (*self).data_end as usize}
    }
    fn data_meta(self) -> usize {
        unsafe { (*self).data_meta as usize}
    }
}

pub struct Packet {
    ctx: XdpCtx,
    offset: usize,
    hdr: &'static ethhdr,
}

impl Packet {
    pub fn new(ctx: XdpCtx) -> Option<Self> {
        let data = ctx.data();
        let data_end = ctx.data_end();
        Some(Packet {
            ctx,
            offset: mem::size_of::<ethhdr>(),
            hdr: Self::pkt_cast::<ethhdr>(data, 0, data_end)?,
        })
    }

    pub fn filter_ip(self) -> Option<IpPacket> {
        match u16::from_be(self.hdr.h_proto) {
            linux_net::ETH_P_IP => IpPacket::new4(self),
            linux_net::ETH_P_IPV6 => IpPacket::new6(self),
            _ => return None,
        }
    }

    // We return un unbounded lifetime because the XdpContext is guaranteed to live for the program
    // duration.
    #[inline(always)]
    fn bpf_read_checked<T: Sized>(&mut self) -> Option<&'static T> {
        let hdr = Self::pkt_cast(self.ctx.data(), self.offset, self.ctx.data_end());
        self.offset += mem::size_of::<ipv6hdr>();
        hdr
    }

    #[inline(always)]
    fn pkt_cast<T: Sized>(data: usize, offset: usize, data_end: usize) -> Option<&'static T> {
        if data + offset + mem::size_of::<T>() > data_end {
            unsafe {
                bpf_vprintk(b"packet overflow offset");
            }
            None
        } else {
            Some(unsafe { mem::transmute::<usize, &T>(data + offset) })
        }
    }
}

pub struct IpPacket {
    p: Packet,
    hdr: IpHdr,
}

impl IpPacket {
    pub fn new4(mut p: Packet) -> Option<IpPacket> {
        let ip = p.bpf_read_checked::<ipv4hdr>()?;
        // The ip header length may be more than sizeof(ipv4hdr) if options are used,
        // so advance the offset to point past the options.
        p.offset += usize::from(ip.ihl() * 4) - mem::size_of::<ipv4hdr>();
        Some(IpPacket {
            p,
            hdr: IpHdr::Ipv4(ip),
        })
    }

    pub fn new6(mut p: Packet) -> Option<IpPacket> {
        let ip = p.bpf_read_checked::<ipv6hdr>()?;
        // TODO: iterate over options and move offset to data ?
        Some(IpPacket {
            p,
            hdr: IpHdr::Ipv6(ip),
        })
    }

    pub fn filter_src(self, src_match: IpNet) -> Option<IpPacket> {
        match (src_match, &self.hdr) {
            (IpNet::v6(_ip6net), IpHdr::Ipv6(_ip6)) => Some(self),
            (IpNet::v4(_ip4net), IpHdr::Ipv4(_ip4)) => Some(self),
            _ => None,
        }
    }

    pub fn filter_tcp(mut self) -> Option<TcpPacket> {
        match self.hdr {
            IpHdr::Ipv4(ip4) if ip4.protocol == linux_net::IPPROTO_TCP as u8 => (),
            IpHdr::Ipv6(ip6) if ip6.nexthdr == linux_net::IPPROTO_TCP as u8 => (),
            _ => return None,
        }

        let tcp = self.p.bpf_read_checked::<tcphdr>()?;
        Some(TcpPacket {
            p: self.p,
            hdr: tcp,
        })
    }
}

pub struct TcpPacket {
    p: Packet,
    pub hdr: &'static tcphdr,
}

impl TcpPacket {
    pub fn filter_syn(self) -> Option<Self> {
        if self.hdr.syn() == 1 {
            Some(self)
        } else {
            None
        }
    }
}
