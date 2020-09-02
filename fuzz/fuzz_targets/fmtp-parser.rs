#![no_main]
use libfuzzer_sys::fuzz_target;
use parser;


fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = parser::fmtp_parse_message(data);
});
