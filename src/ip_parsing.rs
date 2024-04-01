use crate::linux_net::{IpNet, Ipv4Net};

struct ByteRepr {
    parts: [u8; 3],
    idx: usize,
    max: u8,
}

impl ByteRepr {
    const fn new(max: u8) -> ByteRepr {
        ByteRepr {
            parts: [0u8; 3],
            idx: 0,
            max,
        }
    }

    const fn is_dec(chr: u8) -> bool {
        chr >= 48 && chr <= 57
    }

    const fn push_dec_chr(mut self, chr: u8) -> Self {
        if self.idx > 2 {
            panic!("Error parsing byte at number too big");
        }

        if !Self::is_dec(chr) {
            panic!("Error parsing byte, invalid character");
        }

        self.parts[self.idx] = chr - 48;
        self.idx += 1;
        self
    }

    const fn to_u8(&self) -> u8 {
        let output = if self.idx == 0 {
            panic!("Error parsing byte, empty input")
        } else if self.idx == 1 {
            self.parts[0]
        } else if self.idx == 2 {
            10 * self.parts[0] + self.parts[1]
        } else if self.idx == 3 {
            100 * self.parts[0] + 10 * self.parts[1] + self.parts[2]
        } else {
            panic!()
        };

        if output > self.max {
            panic!("Error parsing byte, number too big")
        }

        output
    }
}

const MAX_IPV4_LEN: usize = 18;
pub struct IpParser<'a> {
    input: &'a [u8],
    output: Ipv4Net,
    idx: usize,
    oidx: usize,
}

impl<'a> IpParser<'a> {
    pub const fn new(input: &'a [u8]) -> Self {
        IpParser {
            input,
            idx: 0,
            output: Ipv4Net {
                net: [0, 0, 0, 0],
                mask: 32,
            },
            oidx: 0,
        }
    }

    const fn parse_mask(mut self) -> Self {
        let mut current_byte = ByteRepr::new(32);
        while self.idx < self.input.len() && ByteRepr::is_dec(self.input[self.idx]) {
            current_byte = current_byte.push_dec_chr(self.input[self.idx]);
            self.idx += 1;
        }

        self.output.mask = current_byte.to_u8();
        self
    }

    const fn parse_u8(mut self) -> Self {
        let mut current_byte = ByteRepr::new(255);
        while self.idx < self.input.len() && ByteRepr::is_dec(self.input[self.idx]) {
            current_byte = current_byte.push_dec_chr(self.input[self.idx]);
            self.idx += 1;
        }

        self.output.net[self.oidx] = current_byte.to_u8();
        self.oidx += 1;
        self
    }

    pub const fn parse(self) -> IpNet {
        if self.input.len() > MAX_IPV4_LEN {
            panic!("Error parsing ipv4 address, input too big");
        }

        let mut parser = self.parse_u8();
        while parser.idx < parser.input.len() {
            if parser.input[parser.idx] == b'.' {
                parser.idx += 1;
                parser = parser.parse_u8();
            } else if parser.input[parser.idx] == b'/' {
                parser.idx += 1;
                parser = parser.parse_mask();
            }
        }

        if parser.oidx != parser.output.net.len() {
            panic!("IP address doesn't have enough bytes")
        }

        IpNet::v4(parser.output)
    }
}

