#![no_main]
use hguet_core::{parse_transaction, sha256_hex};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse_transaction(data);
    let second = parse_transaction(data);
    match (first, second) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.transaction_bytes, data.len());
            assert_eq!(a.transaction_sha256, sha256_hex(data));
            assert_eq!(a.static_account_count, a.static_account_keys.len());
            assert_eq!(a.instruction_count, a.compiled_top_level_instructions.len());
            assert_eq!(a.lookup_table_count, a.address_table_lookups.len());
            assert_eq!(a.total_address_count, a.static_account_count + a.unresolved_lookup_addresses);
            assert_eq!(a.required_signatures, a.signature_count);
            assert!(a.required_signatures <= a.static_account_count);
            assert!(a.instruction_count <= 64);
            for (index, ix) in a.compiled_top_level_instructions.iter().enumerate() {
                assert_eq!(ix.instruction_index, index);
                assert!(ix.program_index < a.total_address_count);
                assert!(ix.account_indices.iter().all(|i| *i < a.total_address_count));
            }
            assert_eq!(serde_json::to_value(a).unwrap(), serde_json::to_value(b).unwrap());
        }
        (Err(a), Err(b)) => assert_eq!(a, b),
        _ => panic!("nondeterministic parser result"),
    }
});
