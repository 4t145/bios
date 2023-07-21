pub struct IpV4RadixTree {}

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

pub struct ByteRadix {
    pub prefix: [u8]
}