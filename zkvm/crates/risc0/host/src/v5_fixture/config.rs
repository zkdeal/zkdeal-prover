//! Fixture configuration: the protocol caps, the participant slot layout, the
//! JSON request parser, and the range checks a request has to pass before any
//! room state is built.

use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{bail, Context, Result};
use serde_json::Value;

use super::bytecode::{
    auction_demo_runtime, opcode_gadget_runtime, participant_merkle_runtime, shop_demo_runtime,
    storage_runtime,
};
use super::card::{parse_card_duel_request, CardDuelRequest};
use super::contracts::{
    parse_call_rules, parse_contracts, parse_participant_registry, parse_raw_transactions,
    parse_sender_accounts, FixtureCallRule, FixtureContract, RegistryRequest, RegistrySlots,
    MAX_PREPARED_BATCHES,
};
use super::json::{
    parse_b256, parse_hex_bytes, parse_optional_address, parse_storage_entries, parse_u64,
    parse_u64_or,
};
use super::selectors::{parse_allowed_selectors, parse_optional_call_blocks, FixtureBlockCall};

pub(super) const GAS_LIMIT: u64 = 5_000_000;
pub(super) const MAX_ACTIVE_SIGNERS: u64 = 256;
pub(super) const MAX_TOUCHED_CONTRACTS: u64 = 32;
// The compact witness reserves one explicit absent-account entry, leaving 127
// real room accounts inside the shared 128-account proof envelope.
pub(super) const MAX_RESIDENT_ACCOUNTS: u64 = 127;
pub(super) const MAX_RESIDENT_STORAGE_SLOTS: u64 = 2_048;
pub(super) const MAX_IMPORTED_VARIABLES: u64 = 512;
pub(super) const MAX_GADGET_REPEATS: u64 = 32;
pub(super) const MAX_TOUCHED_PARTICIPANTS: u64 = 128;
pub(super) const MAX_SIGNER_ACCOUNTS: u64 = 16;
/// Production-shaped rooms wait roughly two Ethereum epochs before consuming
/// deposits. The protocol itself refuses a zero-depth room.
pub(super) const PRODUCTION_MINIMUM_DEPOSIT_CONFIRMATIONS: u64 = 64;
/// Imports use the same production finality-delay fallback. The publisher must
/// still require the finalized tag and re-check the source block hash because
/// confirmation depth alone is not a finality proof.
pub(super) const PRODUCTION_MINIMUM_IMPORT_CONFIRMATIONS: u64 = 64;

// The historic registry layout. `bytecode.rs`'s `participant_merkle_runtime`
// is compiled against these literals (`PUSH4 0x3b9aca00`), and every already
// registered cold template committed to them, so they remain the default a
// request inherits when it names no `participantRegistry`.
pub(super) const DEFAULT_PARTICIPANT_ROOT_SLOT: u64 = 1_000_000_000;
pub(super) const DEFAULT_PARTICIPANT_EPOCH_SLOT: u64 = 1_000_000_001;
pub(super) const DEFAULT_PARTICIPANT_COUNT_SLOT: u64 = 1_000_000_002;
pub(super) const DEFAULT_PARTICIPANT_CAPACITY_SLOT: u64 = 1_000_000_003;

pub(super) fn default_registry_slots() -> RegistrySlots {
    RegistrySlots {
        root: U256::from(DEFAULT_PARTICIPANT_ROOT_SLOT),
        epoch: U256::from(DEFAULT_PARTICIPANT_EPOCH_SLOT),
        count: U256::from(DEFAULT_PARTICIPANT_COUNT_SLOT),
        capacity: U256::from(DEFAULT_PARTICIPANT_CAPACITY_SLOT),
    }
}

pub(super) const CARD_DUEL_WORKLOAD: &str = "card-duel";

/// One prepared fixture request, fully parsed and range-checked.
#[derive(Debug)]
pub(super) struct FixtureConfig {
    pub(super) deployment_domain: B256,
    pub(super) room_id: u64,
    pub(super) l1_chain_id: u64,
    pub(super) l1_inclusion_deadline: u64,
    pub(super) active_signers: u64,
    pub(super) authorization_mode: u8,
    pub(super) participant_capacity: u64,
    pub(super) registered_participants: u64,
    pub(super) touched_participants: u64,
    pub(super) touched_contracts: u64,
    pub(super) resident_accounts: u64,
    pub(super) resident_storage_slots: u64,
    pub(super) imported_variables: u64,
    pub(super) workload: String,
    pub(super) gadget_repeats: u64,
    pub(super) custom_call_blocks: Option<Vec<Vec<FixtureBlockCall>>>,
    pub(super) allowed_selectors: Option<Vec<[u8; 4]>>,
    pub(super) initial_storage: Vec<(U256, U256)>,
    pub(super) primary_contract: Option<Address>,
    pub(super) participant_depth: u64,
    pub(super) runtime_code: Bytes,
    pub(super) state_commitment: u8,
    pub(super) max_transactions_per_block: u64,
    pub(super) contracts: Option<Vec<FixtureContract>>,
    pub(super) call_rules: Option<Vec<FixtureCallRule>>,
    pub(super) registry: RegistryRequest,
    pub(super) raw_transactions: Option<Vec<Vec<Bytes>>>,
    /// Which checkpoint of a long-lived room this request prepares, counting
    /// from one. Batch `n` proves blocks `2n-1` and `2n`; blocks `1..=2n-2`
    /// arrive in `rawTransactions` and are replayed to rederive the state the
    /// batch opens at.
    pub(super) batch_index: u64,
    pub(super) sender_accounts: Vec<Address>,
    pub(super) signer_accounts: u64,
    pub(super) card: Option<CardDuelRequest>,
}

pub(super) fn parse_fixture_config(raw: &str) -> Result<FixtureConfig> {
    let config: Value = serde_json::from_str(raw).context("fixture configuration is not JSON")?;
    let deployment_domain = parse_b256(&config, "deploymentDomain")?;
    let room_id = parse_u64(&config, "roomId")?;
    let l1_chain_id = parse_u64(&config, "l1ChainId")?;
    let l1_inclusion_deadline = parse_u64(&config, "l1InclusionDeadline")?;
    let active_signers = parse_u64_or(&config, "activeSigners", 1)?;
    let authorization_mode = match config
        .get("authorizationMode")
        .and_then(Value::as_str)
        .unwrap_or("unanimous-approvers")
    {
        "unanimous-approvers" => 0,
        "validity-only" => 1,
        other => bail!("unsupported authorizationMode '{other}'"),
    };
    let participant_capacity = parse_u64_or(&config, "participantCapacity", 128)?;
    let registered_participants = parse_u64_or(&config, "registeredParticipants", 1)?;
    let touched_participants = parse_u64_or(&config, "touchedParticipants", 1)?;
    let resident_accounts = parse_u64_or(&config, "residentAccounts", 2)?;
    let resident_storage_slots = parse_u64_or(&config, "residentMirrorVariables", 1)?;
    let imported_variables = parse_u64_or(&config, "importedVariables", 0)?;
    let max_transactions_per_block = parse_u64_or(&config, "maxTransactionsPerBlock", 128)?;
    let workload = config
        .get("workload")
        .and_then(Value::as_str)
        .unwrap_or("storage")
        .to_owned();
    let gadget_repeats = parse_u64_or(&config, "gadgetRepeats", 16)?;
    let custom_runtime = config
        .get("runtimeCode")
        .map(|value| parse_hex_bytes(value, "runtimeCode"))
        .transpose()?;
    let contracts = parse_contracts(
        &config,
        MAX_TOUCHED_CONTRACTS as usize,
        MAX_RESIDENT_STORAGE_SLOTS as usize,
    )?;
    let call_rules = parse_call_rules(&config)?;
    let registry = parse_participant_registry(&config, default_registry_slots())?;
    let raw_transactions = parse_raw_transactions(&config)?;
    let batch_index = parse_batch_index(&config, raw_transactions.as_deref())?;
    let sender_accounts = parse_sender_accounts(&config)?;
    let card = parse_card_duel_request(&config)?;
    let custom_call_blocks = parse_optional_call_blocks(&config)?;
    let allowed_selectors = parse_allowed_selectors(&config)?;
    let initial_storage = match config.get("initialStorage") {
        None => Vec::new(),
        Some(raw) => {
            parse_storage_entries(raw, "initialStorage", MAX_RESIDENT_STORAGE_SLOTS as usize)?
        }
    };
    let primary_contract = parse_optional_address(&config, "contractAddress")?;
    let participant_depth = participant_capacity.trailing_zeros() as u64;
    // `build_blocks` picks exactly one source of transactions, in a fixed
    // precedence order. A request that names two of them would have one of them
    // silently discarded and would still come back with a real proof and a real
    // L1 transaction hash for a batch that never contained those calls. That is
    // the one failure mode a prover must never have, so overlapping sources are
    // refused rather than ranked.
    if raw_transactions.is_some() && custom_call_blocks.is_some() {
        bail!(
            "a request supplies both `rawTransactions` and `blockCalls`, but a batch is built \
             from one of them; send only the transactions that are meant to be proven"
        );
    }
    if workload == CARD_DUEL_WORKLOAD && custom_call_blocks.is_some() {
        bail!(
            "the card-duel workload cannot express `blockCalls`: those calls are all signed by \
             one fixture key at a fixed 120,000 gas, which no duel entry point can pay for and \
             which `joinDuel` rejects outright. Send `rawTransactions` signed by the seats \
             themselves instead"
        );
    }
    if workload == CARD_DUEL_WORKLOAD {
        if contracts.is_none() {
            bail!(
                "the card-duel workload requires a `contracts` descriptor naming the duel, \
                 adapter, deckVerifier, handVerifier and stakeToken accounts: a duel room's code \
                 is the real compiled runtime read back from the chain, never host-synthesized \
                 bytecode"
            );
        }
        if card.is_none() {
            bail!("the card-duel workload requires a `cardDuel` object naming entryStake");
        }
        if call_rules.is_none() {
            bail!(
                "the card-duel workload requires `callRules`: the duel CALLs the stake token and \
                 STATICCALLs the proof adapter, and the flat active-member rule set cannot \
                 express either"
            );
        }
    }
    // Per-contract descriptors carry their own runtime code; the flat runtime
    // exists only for the clone-shaped legacy rooms.
    let runtime_code = if contracts.is_some() {
        Bytes::new()
    } else if let Some(runtime) = custom_runtime {
        if runtime.is_empty() {
            bail!("runtimeCode may not be empty");
        }
        runtime
    } else {
        match workload.as_str() {
            "storage" => storage_runtime(),
            "opcode-gadgets" => {
                if gadget_repeats == 0 || gadget_repeats > MAX_GADGET_REPEATS {
                    bail!("gadgetRepeats is outside the certified fixture cap");
                }
                opcode_gadget_runtime(gadget_repeats)
            }
            "participant-merkle" => participant_merkle_runtime(participant_depth),
            "shop-demo" => shop_demo_runtime(),
            "auction-demo" => auction_demo_runtime(),
            other => bail!("unsupported fixture workload '{other}'"),
        }
    };
    let state_commitment = match config
        .get("stateCommitment")
        .and_then(Value::as_str)
        .unwrap_or("mpt")
    {
        "mpt" => 0,
        "sparse-room-tree" => 1,
        other => bail!("unsupported stateCommitment '{other}'"),
    };
    let touched_contracts = match &contracts {
        Some(list) => {
            let declared = list.len() as u64;
            if let Some(requested) = config.get("touchedContracts") {
                let requested = super::json::parse_u64_value(requested, "touchedContracts")?;
                if requested != declared {
                    bail!(
                        "touchedContracts is {requested} but the contracts descriptor names {declared} accounts"
                    );
                }
            }
            declared
        }
        None => parse_u64_or(&config, "touchedContracts", 1)?,
    };
    let signer_accounts = match (&card, &custom_call_blocks) {
        (Some(card), _) if workload == CARD_DUEL_WORKLOAD => card.duelists.len() as u64,
        (_, Some(blocks)) => blocks
            .iter()
            .flatten()
            .map(|call| call.signer_index + 1)
            .max()
            .unwrap_or(1)
            .max(parse_u64_or(&config, "signerAccounts", 1)?),
        _ => parse_u64_or(&config, "signerAccounts", 1)?,
    };
    check_ranges(&CheckedRanges {
        room_id,
        l1_chain_id,
        l1_inclusion_deadline,
        active_signers,
        authorization_mode,
        participant_capacity,
        registered_participants,
        touched_participants,
        touched_contracts,
        resident_accounts,
        resident_storage_slots,
        imported_variables,
        max_transactions_per_block,
        signer_accounts,
        sender_accounts: sender_accounts.len() as u64,
        workload: &workload,
        descriptor_room: contracts.is_some(),
        client_signed: raw_transactions.is_some(),
        registry: registry.slots,
    })?;
    Ok(FixtureConfig {
        deployment_domain,
        room_id,
        l1_chain_id,
        l1_inclusion_deadline,
        active_signers,
        authorization_mode,
        participant_capacity,
        registered_participants,
        touched_participants,
        touched_contracts,
        resident_accounts,
        resident_storage_slots,
        imported_variables,
        workload,
        gadget_repeats,
        custom_call_blocks,
        allowed_selectors,
        initial_storage,
        primary_contract,
        participant_depth,
        runtime_code,
        state_commitment,
        max_transactions_per_block,
        contracts,
        call_rules,
        registry,
        raw_transactions,
        batch_index,
        sender_accounts,
        signer_accounts,
        card,
    })
}

/// Which checkpoint the request prepares, and the one structural rule a
/// continuation has to satisfy.
///
/// `prepare` holds no room state, so batch `n > 1` can only be rebuilt from the
/// blocks that produced the state it opens at. Those blocks have to be in the
/// request, in order, and there have to be exactly `2n` of them: `2n-2` of
/// history and the two the batch itself proves. Saying so here means a
/// misaligned continuation is a request error naming the counts, rather than a
/// `PreRootMismatch` from inside `execute_batch_v5` -- or, far worse, a batch
/// that proves fine natively and is then rejected by
/// `RoomManagerValidationFacet._validateJournal` for a `startL2Block` that does
/// not follow the room's `l2BlockHeight`.
fn parse_batch_index(config: &Value, raw_transactions: Option<&[Vec<Bytes>]>) -> Result<u64> {
    let batch_index = parse_u64_or(config, "batchIndex", 1)?;
    if batch_index == 0 {
        bail!("batchIndex counts from one; batch one is a room's opening batch");
    }
    if batch_index > MAX_PREPARED_BATCHES {
        bail!(
            "batchIndex {batch_index} is past the {MAX_PREPARED_BATCHES}-batch replay bound one \
             request may carry"
        );
    }
    match raw_transactions {
        Some(blocks) => {
            let expected = 2 * batch_index as usize;
            if blocks.len() != expected {
                bail!(
                    "batchIndex {batch_index} proves L2 blocks {} and {}, so the request must \
                     carry all {expected} rawTransactions blocks from block 1 onwards, oldest \
                     first; this one carries {}",
                    2 * batch_index - 1,
                    2 * batch_index,
                    blocks.len()
                );
            }
        }
        None if batch_index != 1 => bail!(
            "batchIndex {batch_index} is a continuation, and a continuation is rebuilt by \
             replaying the room's earlier blocks; only `rawTransactions` can carry them"
        ),
        None => {}
    }
    Ok(batch_index)
}

struct CheckedRanges<'a> {
    room_id: u64,
    l1_chain_id: u64,
    l1_inclusion_deadline: u64,
    active_signers: u64,
    authorization_mode: u8,
    participant_capacity: u64,
    registered_participants: u64,
    touched_participants: u64,
    touched_contracts: u64,
    resident_accounts: u64,
    resident_storage_slots: u64,
    imported_variables: u64,
    max_transactions_per_block: u64,
    signer_accounts: u64,
    sender_accounts: u64,
    workload: &'a str,
    descriptor_room: bool,
    client_signed: bool,
    registry: RegistrySlots,
}

fn check_ranges(checked: &CheckedRanges<'_>) -> Result<()> {
    if checked.room_id == 0 || checked.l1_chain_id == 0 || checked.l1_inclusion_deadline == 0 {
        bail!("roomId, l1ChainId and l1InclusionDeadline must be positive");
    }
    if (checked.authorization_mode == 0
        && (checked.active_signers == 0 || checked.active_signers > MAX_ACTIVE_SIGNERS))
        || (checked.authorization_mode == 1 && checked.active_signers != 0)
    {
        bail!("activeSigners is outside the protocol cap");
    }
    if !power_of_two_capacity(checked.participant_capacity)
        || checked.registered_participants > checked.participant_capacity
    {
        bail!("participant capacity or registered participant count is invalid");
    }
    // An empty registry is a legal opening state: `participant_state_v5` only
    // rejects a zero root or epoch, and a room whose members all join in-room
    // opens with count zero. The generated participant-merkle runtime, by
    // contrast, replaces leaves that must already exist.
    if checked.registered_participants == 0 && checked.workload == "participant-merkle" {
        bail!("the participant-merkle workload needs at least one pre-registered leaf");
    }
    let touch_bound = if checked.registered_participants == 0 {
        checked.participant_capacity
    } else {
        checked.registered_participants
    };
    if checked.touched_participants == 0
        || checked.touched_participants > touch_bound
        || checked.touched_participants > MAX_TOUCHED_PARTICIPANTS
    {
        bail!("touchedParticipants is outside the benchmark cap");
    }
    // Synthesized workloads touch exactly one leaf per block by construction.
    // A room that brings its own contracts or its own signed transactions
    // decides for itself how many leaves a batch moves.
    let multi_touch = checked.workload == "participant-merkle"
        || checked.workload == CARD_DUEL_WORKLOAD
        || checked.descriptor_room
        || checked.client_signed;
    if !multi_touch && checked.touched_participants != 1 {
        bail!(
            "touchedParticipants is only configurable for participant-merkle, card-duel, or a \
             room that supplies `contracts` or `rawTransactions`"
        );
    }
    if checked.touched_contracts == 0 || checked.touched_contracts > MAX_TOUCHED_CONTRACTS {
        bail!("touchedContracts is outside the protocol cap");
    }
    if checked.signer_accounts == 0 || checked.signer_accounts > MAX_SIGNER_ACCOUNTS {
        bail!("signerAccounts must name between one and {MAX_SIGNER_ACCOUNTS} fixture keys");
    }
    let minimum_resident =
        checked.signer_accounts + checked.sender_accounts + checked.touched_contracts;
    if checked.resident_accounts < minimum_resident
        || checked.resident_accounts > MAX_RESIDENT_ACCOUNTS
    {
        bail!("residentAccounts is outside the protocol cap or omits a touched account");
    }
    if checked.resident_storage_slots == 0
        || checked
            .resident_storage_slots
            .saturating_add(checked.imported_variables)
            > MAX_RESIDENT_STORAGE_SLOTS
    {
        bail!("resident mirror variables are outside the protocol cap");
    }
    if checked.imported_variables > MAX_IMPORTED_VARIABLES {
        bail!("importedVariables is outside the certified adapter cap");
    }
    if checked.max_transactions_per_block == 0 || checked.max_transactions_per_block > 128 {
        bail!("maxTransactionsPerBlock must be between one and 128");
    }
    // Without a `contracts` descriptor the registry contract's storage is
    // generated: slots `0..resident+imported` hold mirror variables. A registry
    // slot inside that range is overwritten by the generator, which silently
    // produces a room whose registry metadata is junk.
    if !checked.descriptor_room {
        let generated = U256::from(
            checked
                .resident_storage_slots
                .saturating_add(checked.imported_variables),
        );
        for slot in checked.registry.all() {
            if slot < generated {
                bail!(
                    "participant registry slot {slot} collides with the generated mirror-variable \
                     range 0..{generated}; supply a `contracts` descriptor so the room owns its \
                     storage outright"
                );
            }
        }
    }
    Ok(())
}

fn power_of_two_capacity(value: u64) -> bool {
    (128..=32_768).contains(&value) && value.is_power_of_two()
}
