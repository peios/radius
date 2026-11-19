#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| radius_qualification::campaign::control_sequences(data));
