#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate sampi;

fuzz_target!(|data: &[u8]| {
    let _ = sampi::Sampi::from_bytes(data);
});
