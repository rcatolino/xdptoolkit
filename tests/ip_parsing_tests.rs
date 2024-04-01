use xdptoolkit::{ip_parsing::IpParser, linux_net::IpNet};

#[test]
fn valid_ipv4() {
    assert_eq!(
        IpParser::new(b"0.0.0.0/0").parse(),
        IpNet::new4([0u8; 4], 0)
    )
}

#[test]
fn valid_ipv4_nomask() {
    assert_eq!(
        IpParser::new(b"192.168.19.24").parse(),
        IpNet::new4([192, 168, 19, 24], 32)
    )
}

#[test]
fn valid_ipv4_1() {
    assert_eq!(
        IpParser::new(b"127.0.0.1/0").parse(),
        IpNet::new4([127, 0, 0, 1], 0)
    )
}

#[test]
fn valid_ipv4_2() {
    assert_eq!(
        IpParser::new(b"192.168.19.24/24").parse(),
        IpNet::new4([192, 168, 19, 24], 24)
    )
}

#[test]
fn valid_ipv4_3() {
    assert_eq!(
        IpParser::new(b"192.168.19.24/0").parse(),
        IpNet::new4([192, 168, 19, 24], 0)
    )
}

#[test]
fn valid_ipv4_max_mask() {
    assert_eq!(
        IpParser::new(b"0.0.0.0/32").parse(),
        IpNet::new4([0u8; 4], 32)
    )
}

#[test]
fn valid_ipv4_max_mask_2() {
    assert_eq!(
        IpParser::new(b"255.255.255.255/32").parse(),
        IpNet::new4([255u8; 4], 32)
    )
}

#[test]
#[should_panic]
fn invalid_ipv4_max_mask() {
    let _ = IpParser::new(b"0.0.0.0/33").parse();
}

#[test]
#[should_panic]
fn invalid_ipv4_max_mask2() {
    let _ = IpParser::new(b"0.0.0.0/333").parse();
}

#[test]
#[should_panic]
fn invalid_ipv4_max_mask3() {
    let _ = IpParser::new(b"0.0.0.0/3.1").parse();
}

#[test]
#[should_panic]
fn invalid_ipv4_nomask() {
    let _ = IpParser::new(b"0.0.0.0/").parse();
}

#[test]
#[should_panic]
fn invalid_ipv4_too_many_bytes() {
    let _ = IpParser::new(b"0.0.0.0.0/0").parse();
}

#[test]
#[should_panic]
fn invalid_ipv4_overflow1() {
    let _ = IpParser::new(b"256.0.0.0/0").parse();
}

#[test]
#[should_panic]
fn invalid_ipv4_overflow2() {
    let _ = IpParser::new(b"556.0.0.0/0").parse();
}

#[test]
#[should_panic]
fn invalid_ipv4_not_enough_bytes() {
    let _ = IpParser::new(b"56.0.0/0").parse();
}

#[test]
#[should_panic]
fn invalid_ipv4_not_enough_bytes2() {
    let _ = IpParser::new(b"0/0").parse();
}

#[test]
#[should_panic]
fn invalid_ipv4_not_enough_bytes3() {
    let _ = IpParser::new(b"").parse();
}
