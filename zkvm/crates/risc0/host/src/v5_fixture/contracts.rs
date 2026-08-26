//! Per-contract fixture descriptors, the caller-supplied call rules, and the
//! configurable participant-registry binding.
//!
//! A v5 room is a set of code-pinned accounts, each with its OWN runtime code,
//! its own opening storage and its own certified namespace. The single
//! `runtimeCode` + `touchedContracts` request shape can only ever describe a
//! room whose contracts are byte-identical clones, which is why a five-contract
//! card room needs the descriptor list below. Requests that omit `contracts`
//! are rebuilt into the identical clone-shaped list by `legacy_contracts`, so
//! every already-registered cold template keeps its exact template id.

use alloy_primitives::{Address, Bytes, U256};
use anyhow::{bail, Context, Result};
use serde_json::Value;

use super::bytecode::fixture_address;
use super::config::{FixtureConfig, CARD_DUEL_WORKLOAD};
use super::json::{
    parse_address_value, parse_hex_bytes, parse_selector, parse_storage_entries, parse_u64_value,
    parse_word, parse_word_or,
};

/// Role names a card room binds by, plus the catch-all for generic rooms.
pub(super) const ROLE_DUEL: &str = "duel";
pub(super) const ROLE_ADAPTER: &str = "adapter";
pub(super) const ROLE_DECK_VERIFIER: &str = "deckVerifier";
pub(super) const ROLE_HAND_VERIFIER: &str = "handVerifier";
pub(super) const ROLE_STAKE_TOKEN: &str = "stakeToken";
pub(super) const ROLE_GENERIC: &str = "generic";

/// The five roles a `card-duel` room must name.
pub(super) const CARD_ROOM_ROLES: [&str; 5] = [
    ROLE_DUEL,
    ROLE_ADAPTER,
    ROLE_DECK_VERIFIER,
    ROLE_HAND_VERIFIER,
    ROLE_STAKE_TOKEN,
];

/// One code-pinned room account: its address, its own runtime code, its own
/// opening storage and the certified namespace that covers that storage.
#[derive(Clone, Debug)]
pub(super) struct FixtureContract {
    pub(super) role: String,
    pub(super) address: Address,
    pub(super) runtime_code: Bytes,
    pub(super) storage: Vec<(U256, U256)>,
    pub(super) writable: bool,
    pub(super) prefix_bits: u16,
    pub(super) slot_prefix: U256,
}

/// Role of the synthetic exit-queue account appended to every fixture room.
pub(super) const ROLE_EXIT_QUEUE: &str = "exitQueue";

/// The synthetic exit-queue account every fixture room pins. A validity-only
/// batch is unprovable without a policy exit binding, so the fixture policy
/// always certifies this queue: inert STOP runtime, count slot zero, and a
/// whole-contract writable namespace covering the record region.
pub(super) fn exit_queue_descriptor() -> FixtureContract {
    FixtureContract {
        role: ROLE_EXIT_QUEUE.to_owned(),
        address: exit_queue_address(),
        runtime_code: Bytes::from(vec![0x00]),
        storage: vec![(U256::ZERO, U256::ZERO)],
        writable: true,
        prefix_bits: 0,
        slot_prefix: U256::ZERO,
    }
}

pub(super) fn exit_queue_address() -> Address {
    fixture_address(b"exit-queue", 0)
}

pub(super) fn exit_fallback_recipient() -> Address {
    fixture_address(b"exit-fallback", 0)
}

/// One `CallRuleV5` as the request spells it, before policy construction.
#[derive(Clone, Debug)]
pub(super) struct FixtureCallRule {
    pub(super) caller: Address,
    pub(super) target: Address,
    pub(super) selectors: Vec<[u8; 4]>,
    pub(super) kinds: Vec<u8>,
}

/// The four storage words the guest reads the participant registry out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RegistrySlots {
    pub(super) root: U256,
    pub(super) epoch: U256,
    pub(super) count: U256,
    pub(super) capacity: U256,
}

impl RegistrySlots {
    pub(super) fn all(&self) -> [U256; 4] {
        [self.root, self.epoch, self.count, self.capacity]
    }

    pub(super) fn unique(&self) -> bool {
        let slots = self.all();
        (0..4).all(|i| (i + 1..4).all(|j| slots[i] != slots[j]))
    }
}

/// A parsed `participantRegistry` request object.
#[derive(Clone, Debug)]
pub(super) struct RegistryRequest {
    pub(super) contract: Option<Address>,
    pub(super) slots: RegistrySlots,
}

pub(super) fn parse_contracts(
    config: &Value,
    max_contracts: usize,
    max_slots: usize,
) -> Result<Option<Vec<FixtureContract>>> {
    let Some(raw) = config.get("contracts") else {
        return Ok(None);
    };
    let entries = raw.as_array().context("contracts must be an array")?;
    if entries.is_empty() || entries.len() > max_contracts {
        bail!("contracts must name between one and {max_contracts} room accounts");
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        parsed.push(parse_contract(entry, index, max_slots)?);
    }
    parsed.sort_by_key(|contract| contract.address);
    if parsed.windows(2).any(|pair| pair[0].address == pair[1].address) {
        bail!("contracts contains a duplicate address");
    }
    Ok(Some(parsed))
}

fn parse_contract(entry: &Value, index: usize, max_slots: usize) -> Result<FixtureContract> {
    let object = entry
        .as_object()
        .with_context(|| format!("contracts[{index}] must be an object"))?;
    let role = object
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or(ROLE_GENERIC)
        .to_owned();
    if role.is_empty() {
        bail!("contracts[{index}].role may not be empty");
    }
    let address = parse_address_value(
        object
            .get("address")
            .with_context(|| format!("contracts[{index}].address is required"))?,
        &format!("contracts[{index}].address"),
    )?;
    if address == Address::ZERO {
        bail!("contracts[{index}].address may not be the zero address");
    }
    let runtime_code = parse_hex_bytes(
        object
            .get("runtimeCode")
            .with_context(|| format!("contracts[{index}].runtimeCode is required"))?,
        &format!("contracts[{index}].runtimeCode"),
    )?;
    if runtime_code.is_empty() {
        bail!("contracts[{index}].runtimeCode may not be empty");
    }
    let storage = match object.get("initialStorage") {
        None => Vec::new(),
        Some(raw) => {
            parse_storage_entries(raw, &format!("contracts[{index}].initialStorage"), max_slots)?
        }
    };
    let writable = object
        .get("writable")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let prefix_bits = match object.get("prefixBits") {
        None => 0u16,
        Some(raw) => {
            let bits = parse_u64_value(raw, &format!("contracts[{index}].prefixBits"))?;
            if bits > 256 {
                bail!("contracts[{index}].prefixBits must be at most 256");
            }
            bits as u16
        }
    };
    let slot_prefix = parse_word_or(entry, "slotPrefix", U256::ZERO)?;
    let contract = FixtureContract {
        role,
        address,
        runtime_code,
        storage,
        writable,
        prefix_bits,
        slot_prefix,
    };
    for (slot, _) in &contract.storage {
        if !slot_in_namespace(*slot, contract.slot_prefix, contract.prefix_bits) {
            bail!(
                "contracts[{index}].initialStorage slot {slot:#x} is outside the declared namespace"
            );
        }
    }
    Ok(contract)
}

/// The guest's `slot_has_prefix`, mirrored so a namespace mistake is a parse
/// error rather than a rejection minutes into a proof.
pub(super) fn slot_in_namespace(slot: U256, prefix: U256, prefix_bits: u16) -> bool {
    if prefix_bits == 0 {
        return true;
    }
    if prefix_bits >= 256 {
        return slot == prefix;
    }
    let shift = 256 - usize::from(prefix_bits);
    (slot >> shift) == (prefix >> shift)
}

pub(super) fn parse_call_rules(config: &Value) -> Result<Option<Vec<FixtureCallRule>>> {
    let Some(raw) = config.get("callRules") else {
        return Ok(None);
    };
    let entries = raw.as_array().context("callRules must be an array")?;
    if entries.is_empty() || entries.len() > 64 {
        bail!("callRules must contain between one and 64 rules");
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        parsed.push(parse_call_rule(entry, index)?);
    }
    for (index, rule) in parsed.iter().enumerate() {
        if parsed
            .iter()
            .take(index)
            .any(|other| other.caller == rule.caller && other.target == rule.target)
        {
            bail!("callRules contains a duplicate caller/target pair");
        }
    }
    Ok(Some(parsed))
}

fn parse_call_rule(entry: &Value, index: usize) -> Result<FixtureCallRule> {
    let object = entry
        .as_object()
        .with_context(|| format!("callRules[{index}] must be an object"))?;
    // `Address::ZERO` is the guest's ACTIVE_MEMBER sentinel; "active-member"
    // spells it without a caller having to know that.
    let caller = match object.get("caller") {
        None => Address::ZERO,
        Some(raw) if raw.as_str() == Some("active-member") => Address::ZERO,
        Some(raw) => parse_address_value(raw, &format!("callRules[{index}].caller"))?,
    };
    let target = parse_address_value(
        object
            .get("target")
            .with_context(|| format!("callRules[{index}].target is required"))?,
        &format!("callRules[{index}].target"),
    )?;
    if target == Address::ZERO {
        bail!("callRules[{index}].target may not be the zero address");
    }
    let raw_selectors = object
        .get("selectors")
        .and_then(Value::as_array)
        .with_context(|| format!("callRules[{index}].selectors must be an array"))?;
    if raw_selectors.is_empty() || raw_selectors.len() > 64 {
        bail!("callRules[{index}].selectors must contain between one and 64 selectors");
    }
    let mut selectors = Vec::with_capacity(raw_selectors.len());
    for (position, raw) in raw_selectors.iter().enumerate() {
        selectors.push(parse_selector(
            raw,
            &format!("callRules[{index}].selectors[{position}]"),
        )?);
    }
    selectors.sort();
    let unique = selectors.len();
    selectors.dedup();
    if selectors.len() != unique {
        bail!("callRules[{index}].selectors contains a duplicate selector");
    }
    let mut kinds = match object.get("kinds") {
        None => vec![0u8],
        Some(raw) => {
            let list = raw
                .as_array()
                .with_context(|| format!("callRules[{index}].kinds must be an array"))?;
            let mut kinds = Vec::with_capacity(list.len());
            for (position, kind) in list.iter().enumerate() {
                let kind = parse_u64_value(kind, &format!("callRules[{index}].kinds[{position}]"))?;
                if kind > 2 {
                    bail!("callRules[{index}].kinds must be 0 (CALL), 1 (STATICCALL) or 2 (DELEGATECALL)");
                }
                kinds.push(kind as u8);
            }
            kinds
        }
    };
    kinds.sort_unstable();
    let unique_kinds = kinds.len();
    kinds.dedup();
    if kinds.is_empty() || kinds.len() != unique_kinds {
        bail!("callRules[{index}].kinds must be a non-empty unique list");
    }
    Ok(FixtureCallRule {
        caller,
        target,
        selectors,
        kinds,
    })
}

pub(super) fn parse_participant_registry(
    config: &Value,
    default: RegistrySlots,
) -> Result<RegistryRequest> {
    let Some(raw) = config.get("participantRegistry") else {
        return Ok(RegistryRequest {
            contract: None,
            slots: default,
        });
    };
    let object = raw
        .as_object()
        .context("participantRegistry must be an object")?;
    let contract = match object.get("contract") {
        None => None,
        Some(raw) => Some(parse_address_value(raw, "participantRegistry.contract")?),
    };
    let slot = |name: &str, fallback: U256| -> Result<U256> {
        match object.get(name) {
            None => Ok(fallback),
            Some(raw) => parse_word(raw, &format!("participantRegistry.{name}")),
        }
    };
    let slots = RegistrySlots {
        root: slot("rootSlot", default.root)?,
        epoch: slot("epochSlot", default.epoch)?,
        count: slot("countSlot", default.count)?,
        capacity: slot("capacitySlot", default.capacity)?,
    };
    if !slots.unique() {
        bail!("participantRegistry must name four distinct slots");
    }
    Ok(RegistryRequest { contract, slots })
}

/// The longest block history one request may carry: `MAX_PREPARED_BATCHES`
/// batches of two blocks each. Every block before the requested batch is
/// replayed natively inside `prepare`, so the bound is what keeps a single
/// request's work finite.
pub(super) const MAX_PREPARED_BATCHES: u64 = 64;
pub(super) const MAX_PREPARED_BLOCKS: usize = 2 * MAX_PREPARED_BATCHES as usize;

/// Already-signed EIP-1559 envelopes, two blocks per batch. A room whose
/// transactions were signed by real client keys never needs the host to forge
/// a signature on a player's behalf.
///
/// A room that is taking its second or later checkpoint sends *every* block it
/// has ever proved, oldest first, followed by the two blocks of the batch it
/// wants now -- `2 * batchIndex` blocks in all. `prepare` replays the earlier
/// ones to rederive the state the new batch opens at, which is what keeps it a
/// pure function of its request instead of a server that remembers rooms.
pub(super) fn parse_raw_transactions(config: &Value) -> Result<Option<Vec<Vec<Bytes>>>> {
    let Some(raw) = config.get("rawTransactions") else {
        return Ok(None);
    };
    let blocks = raw
        .as_array()
        .context("rawTransactions must contain an array of room blocks")?;
    if blocks.len() < 2 || blocks.len() % 2 != 0 || blocks.len() > MAX_PREPARED_BLOCKS {
        bail!(
            "rawTransactions must contain an even number of room blocks, between two and \
             {MAX_PREPARED_BLOCKS}: a batch is two blocks, and a continuation carries every \
             earlier block too. This request carries {}",
            blocks.len()
        );
    }
    let mut parsed = Vec::with_capacity(blocks.len());
    for (block_index, raw_block) in blocks.iter().enumerate() {
        let list = raw_block
            .as_array()
            .with_context(|| format!("rawTransactions[{block_index}] must be an array"))?;
        if list.is_empty() || list.len() > 32 {
            bail!("each rawTransactions entry must contain between one and 32 transactions");
        }
        let mut block = Vec::with_capacity(list.len());
        for (index, entry) in list.iter().enumerate() {
            let bytes =
                parse_hex_bytes(entry, &format!("rawTransactions[{block_index}][{index}]"))?;
            if bytes.len() < 32 {
                bail!("rawTransactions[{block_index}][{index}] is not a signed transaction");
            }
            block.push(bytes);
        }
        parsed.push(block);
    }
    Ok(Some(parsed))
}

/// Extra externally-owned accounts the opening state must fund, named by the
/// caller when the room's transactions were signed elsewhere.
pub(super) fn parse_sender_accounts(config: &Value) -> Result<Vec<Address>> {
    let Some(raw) = config.get("senderAccounts") else {
        return Ok(Vec::new());
    };
    let entries = raw.as_array().context("senderAccounts must be an array")?;
    if entries.len() > 32 {
        bail!("senderAccounts may name at most 32 accounts");
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        parsed.push(parse_address_value(
            entry,
            &format!("senderAccounts[{index}]"),
        )?);
    }
    Ok(parsed)
}

/// The clone-shaped contract list every request that predates `contracts`
/// implies: `touchedContracts` synthetic addresses (the first replaced by
/// `contractAddress`), all sharing one runtime and one whole-contract writable
/// namespace. Reproducing it exactly is what keeps existing template ids
/// stable.
pub(super) fn legacy_contracts(
    touched_contracts: u64,
    primary_contract: Option<Address>,
    runtime_code: &Bytes,
) -> (Vec<FixtureContract>, Address) {
    let mut addresses = (0..touched_contracts)
        .map(|index| fixture_address(b"room-contract", index))
        .collect::<Vec<_>>();
    if let Some(address) = primary_contract {
        addresses[0] = address;
    }
    addresses.sort();
    // The primary address is the registry host even when it does not sort
    // first. Reading `addresses[0]` after the sort silently rebinds the
    // registry (and the L1 mirror destination) to a synthetic address whenever
    // a caller names a contract that sorts later.
    let registry = primary_contract.unwrap_or(addresses[0]);
    let contracts = addresses
        .into_iter()
        .map(|address| FixtureContract {
            role: ROLE_GENERIC.to_owned(),
            address,
            runtime_code: runtime_code.clone(),
            storage: Vec::new(),
            writable: true,
            prefix_bits: if address == registry { 0 } else { 256 },
            slot_prefix: U256::ZERO,
        })
        .collect();
    (contracts, registry)
}

/// The single descriptor carrying `role`, or `None`.
pub(super) fn contract_with_role<'a>(
    contracts: &'a [FixtureContract],
    role: &str,
) -> Option<&'a FixtureContract> {
    contracts.iter().find(|contract| contract.role == role)
}

/// The pinned contracts and the account the participant registry lives on,
/// resolved from a parsed request: either the caller's own descriptors or the
/// clone-shaped legacy list a request that names none implies.
pub(super) struct RoomContracts {
    pub(super) contracts: Vec<FixtureContract>,
    pub(super) registry: Address,
    pub(super) descriptor_room: bool,
}

pub(super) fn resolve_contracts(config: &FixtureConfig) -> Result<RoomContracts> {
    let Some(descriptors) = &config.contracts else {
        let (contracts, registry) = legacy_contracts(
            config.touched_contracts,
            config.primary_contract,
            &config.runtime_code,
        );
        return Ok(RoomContracts {
            contracts,
            registry,
            descriptor_room: false,
        });
    };
    if config.workload == CARD_DUEL_WORKLOAD {
        for role in CARD_ROOM_ROLES {
            if contract_with_role(descriptors, role).is_none() {
                bail!(
                    "the card-duel workload needs a contracts entry with role '{role}'; a duel \
                     room is the duel, its proof adapter, the deck and hand verifiers and the \
                     stake token"
                );
            }
        }
    }
    let registry = match config.registry.contract {
        Some(address) => address,
        None => match contract_with_role(descriptors, ROLE_DUEL) {
            Some(contract) => contract.address,
            None => descriptors[0].address,
        },
    };
    if !descriptors
        .iter()
        .any(|contract| contract.address == registry)
    {
        bail!("participantRegistry.contract {registry} is not one of the room's contracts");
    }
    Ok(RoomContracts {
        contracts: descriptors.clone(),
        registry,
        descriptor_room: true,
    })
}
