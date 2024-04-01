use std::env;
use std::path::PathBuf;

use bindgen::callbacks::{IntKind, ParseCallbacks};

#[derive(Debug)]
struct CustomParser();

impl ParseCallbacks for CustomParser {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        if name.starts_with("ETH_P") {
            Some(IntKind::U16)
        } else if name.starts_with("IPPROTO_") {
            Some(IntKind::U8)
        } else {
            None
        }
    }
}

fn main() {
    let bindings = bindgen::Builder::default()
        .header("net.h")
        .use_core()
        .no_default("*")
        .no_debug("*")
        .no_convert_floats()
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_type("ethhdr")
        .allowlist_type("ipv4hdr")
        .allowlist_type("ipv6hdr")
        .allowlist_type("tcphdr")
        .allowlist_type("sockaddr_in")
        .allowlist_var("ETH_P_IP")
        .allowlist_var("ETH_P_IPV6")
        .allowlist_var("IPPROTO_.*")
        .allowlist_type("xdp_md")
        .allowlist_type("xdp_action")
        .constified_enum_module("xdp_action")
        .parse_callbacks(Box::new(CustomParser()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
