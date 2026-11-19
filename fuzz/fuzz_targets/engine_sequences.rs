#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| radius_qualification::campaign::engine_sequences(data));
