//! The two room blocks a prepared fixture proves, and -- for a room taking its
//! second or later checkpoint -- the earlier blocks `prepare` replays first.
//!
//! Five sources, in precedence order: transactions the client already signed,
//! caller-supplied calldata, the card duel, the participant-merkle sweep, and
//! the generic two-calls-per-contract default. Only the first of those can
//! carry history: the other four synthesize exactly one batch.

use alloy_primitives::{keccak256, Address, Bytes, B256};
use anyhow::Result;
use std::collections::BTreeMap;

use super::card::build_card_duel;
use super::config::{FixtureConfig, CARD_DUEL_WORKLOAD};
use super::contracts::{FixtureContract, ROLE_EXIT_QUEUE};
use super::merkle::{participant_proof, update_participant_tree};
use super::raw::{client_calls, client_senders, ClientTransaction};
use super::signing::{sign_call, sign_calldata_as, sign_participant_update_call, signer_address};

/// The prepared batch's transactions plus what the policy must permit.
pub(super) struct RoomBlocks {
    /// Every block the room already proved, oldest first, replayed by
    /// `prepare` to rederive the state this batch opens at. Empty for a room's
    /// opening batch, which opens at the cold template's initial state.
    pub(super) history: Vec<Vec<Bytes>>,
    pub(super) first: Vec<Bytes>,
    pub(super) second: Vec<Bytes>,
    /// The accounts the batch is signed by, when they are not simply fixture
    /// signer zero: the duel's seat owners for a host-scripted plan, the
    /// recovered senders for a client-signed one.
    pub(super) owners: Vec<Address>,
    /// `(target, selector)` pairs the blocks call, cross-checked against the
    /// certified policy before anything is executed.
    pub(super) calls: Vec<(Address, [u8; 4])>,
    /// Whether the blocks consume participant Merkle proofs, and therefore
    /// require the opening root to match the tree the host built.
    pub(super) uses_participant_proofs: bool,
}

impl RoomBlocks {
    pub(super) fn transaction_count(&self) -> u64 {
        (self.first.len() + self.second.len()) as u64
    }
}

pub(super) fn build_blocks(
    config: &FixtureConfig,
    chain_id: u64,
    contracts: &[FixtureContract],
    registry_contract: Address,
    client: &[ClientTransaction],
    levels: &mut Vec<Vec<B256>>,
) -> Result<RoomBlocks> {
    if let Some(blocks) = &config.raw_transactions {
        // The envelopes are already decoded and admission-checked by
        // `raw::inspect_client_transactions`, so a client-signed batch reaches
        // the same `callRules` cross-check and the same resident-account
        // accounting a host-scripted one does. The bytes are passed through
        // untouched: re-encoding them would break the signature.
        //
        // `config.batch_index` already pinned the length at `2 * batchIndex`,
        // so the batch is always the last two blocks and everything before it
        // is history to replay.
        let batch = blocks.len() - 2;
        return Ok(RoomBlocks {
            history: blocks[..batch].to_vec(),
            first: blocks[batch].clone(),
            second: blocks[batch + 1].clone(),
            owners: client_senders(client),
            calls: client_calls(client),
            // A duel's calldata carries `MerkleParticipants` sibling paths the
            // client derived from the room's own tree. If the opening root slot
            // were overridden away from the tree the host generates, every one
            // of those paths would be stale and the batch would fail natively
            // with nothing pointing at the cause.
            uses_participant_proofs: config.workload == CARD_DUEL_WORKLOAD,
        });
    }
    if let Some(blocks) = &config.custom_call_blocks {
        let mut nonces = BTreeMap::<u64, u64>::new();
        let mut sign = |call: &super::selectors::FixtureBlockCall| {
            let nonce = nonces.entry(call.signer_index).or_default();
            let raw = sign_calldata_as(
                chain_id,
                call.signer_index,
                *nonce,
                registry_contract,
                call.calldata.clone(),
                call.gas_limit,
            );
            *nonce += 1;
            raw
        };
        let first = blocks[0].iter().map(&mut sign).collect::<Vec<_>>();
        let second = blocks[1].iter().map(&mut sign).collect::<Vec<_>>();
        let calls = blocks
            .iter()
            .flatten()
            .map(|call| {
                (
                    registry_contract,
                    <[u8; 4]>::try_from(&call.calldata[..4]).expect("custom calls have selectors"),
                )
            })
            .collect();
        let owners = nonces
            .keys()
            .copied()
            .map(signer_address)
            .collect::<Vec<_>>();
        return Ok(RoomBlocks {
            history: Vec::new(),
            first,
            second,
            owners,
            calls,
            uses_participant_proofs: false,
        });
    }
    if config.workload == CARD_DUEL_WORKLOAD {
        let request = config
            .card
            .as_ref()
            .expect("card-duel requests carry a cardDuel object");
        let plan = build_card_duel(
            chain_id,
            registry_contract,
            config.participant_capacity,
            request,
            levels,
        )?;
        return Ok(RoomBlocks {
            history: Vec::new(),
            first: plan.first,
            second: plan.second,
            owners: plan.owners,
            calls: plan.calls,
            uses_participant_proofs: true,
        });
    }
    if config.workload == "participant-merkle" {
        let transactions = participant_transactions(config, chain_id, registry_contract, levels);
        let split = usize::try_from(config.touched_participants.div_ceil(2))
            .expect("participant split fits usize");
        return Ok(RoomBlocks {
            history: Vec::new(),
            first: transactions[..split].to_vec(),
            second: transactions[split..].to_vec(),
            owners: Vec::new(),
            calls: vec![(registry_contract, [0x12, 0x34, 0x56, 0x78])],
            uses_participant_proofs: true,
        });
    }
    // The inert exit queue is pinned by every room but never called: the
    // workload transactions and their nonce schedule stay those of the
    // request's own contracts.
    let called = contracts
        .iter()
        .filter(|contract| contract.role != ROLE_EXIT_QUEUE)
        .collect::<Vec<_>>();
    let first = called
        .iter()
        .enumerate()
        .map(|(index, contract)| {
            sign_call(chain_id, index as u64, contract.address, 9 + index as u64)
        })
        .collect::<Vec<_>>();
    let second = called
        .iter()
        .enumerate()
        .map(|(index, contract)| {
            sign_call(
                chain_id,
                config.touched_contracts + index as u64,
                contract.address,
                10 + index as u64,
            )
        })
        .collect::<Vec<_>>();
    Ok(RoomBlocks {
        history: Vec::new(),
        first,
        second,
        owners: Vec::new(),
        calls: called
            .iter()
            .map(|contract| (contract.address, [0x12, 0x34, 0x56, 0x78]))
            .collect(),
        uses_participant_proofs: false,
    })
}

fn participant_transactions(
    config: &FixtureConfig,
    chain_id: u64,
    contract: Address,
    levels: &mut Vec<Vec<B256>>,
) -> Vec<Bytes> {
    (0..config.touched_participants)
        .map(|index| {
            let position = usize::try_from(index).expect("participant index fits usize");
            let old_leaf = levels[0][position];
            let proof = participant_proof(levels, position);
            let mut update = b"zkdeal/v5/participant-update".to_vec();
            update.extend_from_slice(&index.to_be_bytes());
            update.extend_from_slice(old_leaf.as_slice());
            let new_leaf = keccak256(update);
            let raw = sign_participant_update_call(
                chain_id, index, contract, index, old_leaf, new_leaf, &proof,
            );
            update_participant_tree(levels, position, new_leaf);
            raw
        })
        .collect()
}
