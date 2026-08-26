//! Cross-language golden vector for the v5 cold-template genesis frame.
//!
//! The frame is the exact byte string a room creator publishes on L1
//! (`ColdTemplateDataPublished`) and the guest decodes for the registration
//! statement, so its layout is a cross-language contract. The room-fallback
//! reconstructor (TypeScript) decodes the checked-in copy back into the policy
//! and the complete compact state and must reach `initial_state_root` when it
//! rebuilds its engine, so the fixture state carries the TS engine's invariable
//! genesis accounts: the 1-wei Osaka precompile seed of
//! `l2-engine/src/precompiles.ts` (`ensureL2Precompiles`).
//!
//! Regenerate the checked-in JSON with:
//!   cargo test -p stf-core --test room_v5 emit_cold_template_vectors -- --ignored
//! and copy the emitted file byte-for-byte to the consumer twin at
//! `app-node/packages/room-fallback/test/fixtures/cold-template-frame-v5.json`.

use std::path::PathBuf;

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::EMPTY_ROOT_HASH;
use serde::Serialize;
use sha2::{Digest, Sha256};

use stf_core::{execute_cold_template_v5, osaka_precompile_addresses, StateMap};
use stf_types::{
    cold_template_id_v5, execution_policy_hash_v5, AccountState, CallRuleV5,
    CertifiedImportBindingV5, CodeCommitmentV5, ColdTemplateInputV5, CompactAccountWitnessV4,
    CompactStateWitnessV4, CompactStorageWitnessV4, ExecutionPolicyV5, ExitAssetBindingV5,
    ExitBindingV5, ParticipantRegistryBindingV5, StorageNamespaceV5,
};

use crate::support::{
    exit_queue_runtime_code, sender, EXIT_CALL_SELECTOR, EXIT_QUEUE_COUNT_SLOT,
    EXIT_QUEUE_RECORDS_BASE_SLOT,
};
use crate::witness::exit_queue;

/// Fixture identity words, matching the room_v5 batch witnesses.
const PROOF_PROGRAM_ID: B256 = B256::repeat_byte(0x33);
const PROOF_SYSTEM_VERSION: B256 = B256::repeat_byte(0x55);

/// Frame magic of the canonical genesis package. stf-core cannot depend on the
/// host crate, so the `magic ++ bincode` framing of
/// `crates/risc0/host/src/witness.rs::cold_template_input_bytes_v5` is
/// replicated here; the pin test asserts the bincode leg round-trips.
const COLD_TEMPLATE_MAGIC_V5: &[u8; 8] = b"ZKDV5CLD";

/// sha256 over the frame and its derived identity words. The TypeScript mirror
/// pins the same value. Regenerate by running `emit_cold_template_vectors` and
/// copying the printed digest.
const DIGEST: &str = "0x39a427e4d635a924b3d793512cb54c8fc79bcfbda8014c7c02c7068ecd8c1425";

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/room_v5/vectors/cold-template-frame-v5.json")
}

fn app_contract() -> Address {
    Address::repeat_byte(0x44)
}

/// calldata[4..36] -> storage[0]; the same room app the batch witnesses pin.
fn app_runtime_code() -> Bytes {
    Bytes::from(vec![0x60, 0x04, 0x35, 0x5f, 0x55, 0x00])
}

fn l1_source() -> Address {
    Address::repeat_byte(0x51)
}

/// A keccak-derived mapping slot shape: top bit set, so the vector exercises
/// 32-byte big-endian slot keys past the low integer range.
fn high_bit_slot() -> U256 {
    (U256::from(1) << 255) | U256::from(0x2a)
}

/// The complete room-local genesis: the TS engine's 1-wei precompile seed, the
/// policy-pinned app contract (participant registry + one high-bit mapping
/// leaf), the exit queue at count zero, and one funded member EOA. Zero-valued
/// slots (queue count, import mirror) are omitted: they are absences in the
/// room trie and `compactStateFromLiveEngine` never declares them unrequired.
fn genesis_accounts() -> Vec<(Address, AccountState)> {
    let mut state = osaka_precompile_addresses()
        .into_iter()
        .map(|address| {
            (
                address,
                AccountState {
                    nonce: 0,
                    balance: U256::from(1),
                    code: Bytes::new(),
                    storage: vec![],
                },
            )
        })
        .collect::<Vec<_>>();
    state.push((
        app_contract(),
        AccountState {
            nonce: 1,
            balance: U256::ZERO,
            code: app_runtime_code(),
            storage: vec![
                // Participant registry root/epoch/count/capacity; the root
                // value has its top bit set to pin high-bit storage values.
                (
                    U256::from(10),
                    U256::from_be_bytes(B256::repeat_byte(0xa5).0),
                ),
                (U256::from(11), U256::from(1)),
                (U256::from(12), U256::from(1)),
                (U256::from(13), U256::from(2)),
                (high_bit_slot(), U256::from(1_000_000)),
            ],
        },
    ));
    state.push((
        exit_queue(),
        AccountState {
            nonce: 1,
            balance: U256::ZERO,
            code: exit_queue_runtime_code(),
            storage: vec![],
        },
    ));
    state.push((
        sender(),
        AccountState {
            nonce: 0,
            balance: U256::from(10u64).pow(U256::from(20u64)),
            code: Bytes::new(),
            storage: vec![],
        },
    ));
    state.sort_by_key(|(address, _)| *address);
    state
}

/// A small but complete certified policy over the genesis accounts: both
/// contracts code-pinned, member calls into the app and the exit queue, one
/// certified L1 storage-mirror import into the app contract, the registry
/// binding and a native-asset exit binding.
fn policy() -> ExecutionPolicyV5 {
    ExecutionPolicyV5 {
        state_commitment: 0,
        max_blocks_per_batch: 4,
        max_transactions_per_block: 32,
        max_gas_per_block: 1_000_000,
        max_memory_bytes: 16 * 1024 * 1024,
        allow_contract_creation: false,
        allow_self_destruct: false,
        code: vec![
            CodeCommitmentV5 {
                address: app_contract(),
                runtime_code_hash: keccak256(app_runtime_code()),
            },
            CodeCommitmentV5 {
                address: exit_queue(),
                runtime_code_hash: keccak256(exit_queue_runtime_code()),
            },
        ],
        calls: vec![
            CallRuleV5 {
                caller: Address::ZERO,
                target: app_contract(),
                selectors: vec![[0x12, 0x34, 0x56, 0x78]],
                kinds: vec![0],
            },
            CallRuleV5 {
                caller: Address::ZERO,
                target: exit_queue(),
                selectors: vec![EXIT_CALL_SELECTOR],
                kinds: vec![0],
            },
        ],
        storage: vec![
            StorageNamespaceV5 {
                contract: app_contract(),
                slot_prefix: U256::ZERO,
                prefix_bits: 0,
                writable: true,
            },
            StorageNamespaceV5 {
                contract: exit_queue(),
                slot_prefix: U256::ZERO,
                prefix_bits: 0,
                writable: true,
            },
        ],
        imports: vec![CertifiedImportBindingV5 {
            adapter_id: keccak256(b"zkdeal/test-adapter/l1-storage-mirror"),
            adapter_version: B256::with_last_byte(1),
            source: l1_source(),
            source_key: U256::from(2),
            // Slot 0x20 keeps the mirror clear of the registry slots 10..13.
            room_contract: app_contract(),
            room_slot: U256::from(0x20),
        }],
        participant_registry: Some(ParticipantRegistryBindingV5 {
            contract: app_contract(),
            root_slot: U256::from(10),
            epoch_slot: U256::from(11),
            count_slot: U256::from(12),
            capacity_slot: U256::from(13),
        }),
        exit: Some(ExitBindingV5 {
            queue_contract: exit_queue(),
            count_slot: EXIT_QUEUE_COUNT_SLOT,
            records_base_slot: EXIT_QUEUE_RECORDS_BASE_SLOT,
            assets: vec![ExitAssetBindingV5 {
                asset: Address::ZERO,
                kind: 0,
                token: Address::ZERO,
                balance_slot: U256::ZERO,
            }],
            fallback_recipient: sender(),
        }),
    }
}

fn compact_state_of(state: &[(Address, AccountState)]) -> CompactStateWitnessV4 {
    // The canonical absent zero account, exactly as the TS composer's
    // `compactStateFromLiveEngine` always declares it.
    let mut accounts = vec![CompactAccountWitnessV4 {
        address: Address::ZERO,
        exists: false,
        canonical_storage_root: EMPTY_ROOT_HASH,
        ..Default::default()
    }];
    accounts.extend(state.iter().map(|(address, account)| {
        CompactAccountWitnessV4 {
            address: *address,
            exists: true,
            nonce: account.nonce,
            balance: account.balance,
            code: account.code.clone(),
            canonical_storage_root: EMPTY_ROOT_HASH,
            account_proof: vec![],
            storage: account
                .storage
                .iter()
                .map(|(slot, value)| CompactStorageWitnessV4 {
                    slot: *slot,
                    value: *value,
                    proof: vec![],
                })
                .collect(),
        }
    }));
    accounts.sort_by_key(|account| account.address);
    CompactStateWitnessV4 {
        canonical_state_root: B256::ZERO,
        accounts,
    }
}

/// See `COLD_TEMPLATE_MAGIC_V5`: `crates/risc0/host/src/witness.rs` is the
/// framing authority.
fn frame_v5(input: &ColdTemplateInputV5) -> Vec<u8> {
    let encoded = bincode::serialize(input).expect("serialize v5 cold-template witness");
    let mut framed = Vec::with_capacity(COLD_TEMPLATE_MAGIC_V5.len() + encoded.len());
    framed.extend_from_slice(COLD_TEMPLATE_MAGIC_V5);
    framed.extend_from_slice(&encoded);
    framed
}

/// Build the genuine genesis package. `execute_cold_template_v5` runs the full
/// guest validation (compact-state authentication, root re-derivation, policy
/// certification), so an invalid fixture can never be emitted.
fn build() -> (ColdTemplateInputV5, Vec<u8>, B256) {
    let accounts = genesis_accounts();
    let initial_state_root = StateMap::from_input(&accounts).state_root();
    let policy = policy();
    let policy_hash = execution_policy_hash_v5(&policy);
    let input = ColdTemplateInputV5 {
        template_id: cold_template_id_v5(initial_state_root, policy_hash, PROOF_SYSTEM_VERSION),
        initial_state_root,
        policy_hash,
        proof_program_id: PROOF_PROGRAM_ID,
        proof_system_version: PROOF_SYSTEM_VERSION,
        policy,
        compact_state: compact_state_of(&accounts),
    };
    let frame = frame_v5(&input);
    let genesis_data_hash = keccak256(&frame);
    execute_cold_template_v5(&input, genesis_data_hash)
        .expect("the emitted genesis package is guest-valid");
    (input, frame, genesis_data_hash)
}

fn digest(frame: &[u8], input: &ColdTemplateInputV5, genesis_data_hash: B256) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(frame);
    hasher.update(genesis_data_hash.as_slice());
    hasher.update(input.template_id.as_slice());
    hasher.update(input.initial_state_root.as_slice());
    hasher.update(input.policy_hash.as_slice());
    hasher.update(input.proof_program_id.as_slice());
    hasher.update(input.proof_system_version.as_slice());
    let bytes: [u8; 32] = hasher.finalize().into();
    B256::from(bytes)
}

#[derive(Serialize)]
struct VectorsJson {
    schema_version: u32,
    source: String,
    note: String,
    frame_hex: Bytes,
    genesis_data_hash: B256,
    template_id: B256,
    initial_state_root: B256,
    policy_hash: B256,
    proof_program_id: B256,
    proof_system_version: B256,
    compact_state: CompactStateWitnessV4,
    digest: B256,
}

fn document() -> VectorsJson {
    let (input, frame, genesis_data_hash) = build();
    let digest = digest(&frame, &input, genesis_data_hash);
    VectorsJson {
        schema_version: 1,
        source: "stf-core/tests/room_v5/cold_template_vectors.rs (emit_cold_template_vectors)"
            .to_string(),
        note: "frame = b\"ZKDV5CLD\" ++ bincode(ColdTemplateInputV5); genesis_data_hash = \
               keccak256(frame); digest = sha256( frame ++ genesis_data_hash ++ template_id ++ \
               initial_state_root ++ policy_hash ++ proof_program_id ++ proof_system_version ); \
               byte-identical twin at \
               app-node/packages/room-fallback/test/fixtures/cold-template-frame-v5.json"
            .to_string(),
        frame_hex: Bytes::from(frame),
        genesis_data_hash,
        template_id: input.template_id,
        initial_state_root: input.initial_state_root,
        policy_hash: input.policy_hash,
        proof_program_id: input.proof_program_id,
        proof_system_version: input.proof_system_version,
        compact_state: input.compact_state,
        digest,
    }
}

#[test]
#[ignore]
fn emit_cold_template_vectors() {
    let document = document();
    let json = serde_json::to_string_pretty(&document).expect("vectors serialize");
    let path = vectors_path();
    std::fs::create_dir_all(path.parent().expect("vectors dir has a parent"))
        .expect("create vectors dir");
    std::fs::write(&path, format!("{json}\n")).expect("write cold-template vectors");
    println!("cold-template digest = {}", document.digest);
}

#[test]
fn vectors_match_the_emitted_cold_template() {
    let (input, frame, genesis_data_hash) = build();

    // The replicated framing must round-trip through the same bincode line the
    // host and guest pin, or the emitted frame is not the canonical encoding.
    let decoded: ColdTemplateInputV5 = bincode::deserialize(
        frame
            .strip_prefix(COLD_TEMPLATE_MAGIC_V5)
            .expect("frame starts with the cold-template magic"),
    )
    .expect("frame body is canonical bincode");
    assert_eq!(decoded, input, "cold-template frame does not round-trip");

    assert_eq!(
        digest(&frame, &input, genesis_data_hash).to_string(),
        DIGEST,
        "cold-template vector digest drifted"
    );

    // Byte-equality with the checked-in consumer copy.
    let json = serde_json::to_string_pretty(&document()).expect("vectors serialize");
    let on_disk = std::fs::read_to_string(vectors_path()).expect(
        "run `cargo test -p stf-core --test room_v5 emit_cold_template_vectors -- --ignored` to \
         generate the checked-in copy",
    );
    assert_eq!(
        on_disk,
        format!("{json}\n"),
        "checked-in cold-template vectors differ from the emitter output"
    );
}
