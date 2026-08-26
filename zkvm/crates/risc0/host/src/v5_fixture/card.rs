//! The `card-duel` workload: real calldata against the real compiled
//! `HiddenCardDuelV5` runtime.
//!
//! Nothing here is synthesized bytecode. The room's contracts arrive as
//! descriptors carrying the runtime the deployer read back from the chain, and
//! this module builds the ABI calldata for the entry points a duel opens with:
//! two `registerDuelist` calls that move real `RoomToken` escrow and write two
//! participant leaves, then `openDuel` and `joinDuel` from two DIFFERENT
//! signers -- `CardDuelBase.joinDuel` rejects a second seat whose owner equals
//! the first, so a one-key fixture can never express a duel.
//!
//! Every leaf this module predicts mirrors `MerkleParticipants.participantHash`
//! and `CardDuelBase._stake`. A mistake in that mirror is not silent: the
//! sibling path it feeds the next call stops matching `participantRoot` and
//! `prepare` fails inside its own native `execute_batch_v5` validation, before
//! any proof is attempted.
//!
//! WHAT THE COLD-STATE BUILDER MUST SEED. The compact room witness has to name
//! every storage slot the batch touches, so the `contracts` descriptor for a
//! duel room carries more than the participant registry:
//!   * duel slots 0-3 (registry), 4 `roomApplicationDomain`, 5 `proofDomain`,
//!     6 `duelCount` and 8 `_locked` -- `_locked` MUST open at 1 or every
//!     `nonReentrant` entry point reverts;
//!   * duel slots `keccak256(duelId . 7) + 0..17`, the `_duels[duelId]` struct:
//!     one packed header word, `pot`, and two eight-word `Seat`s;
//!   * stake-token `balanceOf` for both duelists AND for the duel itself (the
//!     escrow destination, even at zero), plus `allowance[duelist][duel]`.
//! A missing slot surfaces as `UndeclaredStorage { address, slot }` from the
//! executor during `prepare`, never as a bad proof.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use anyhow::{bail, Context, Result};
use serde_json::Value;

use super::json::{parse_address_value, parse_u64_or, parse_u64_value, parse_word};
use super::merkle::{participant_proof, update_participant_tree};
use super::signing::{sign_calldata_as, signer_address};

/// `MerkleParticipants.Participant`, spelled once.
const PARTICIPANT_TUPLE: &str =
    "(uint64,address,address,uint64,uint256,uint256,uint256,uint64,bytes32,bool)";

const DEFAULT_REGISTER_GAS: u64 = 700_000;
const DEFAULT_MOVE_GAS: u64 = 600_000;
/// Two seats. `CardDuelLibV5.Duel` has exactly two.
pub(super) const CARD_ROOM_PLAYERS: usize = 2;

#[derive(Clone, Debug)]
pub(super) struct CardDuelist {
    pub(super) index: u64,
    pub(super) signer_index: u64,
    pub(super) session_key: Option<Address>,
}

#[derive(Clone, Debug)]
pub(super) struct CardDuelRequest {
    pub(super) entry_stake: U256,
    pub(super) funded_amount: U256,
    pub(super) session_expiry: u64,
    pub(super) register_gas: u64,
    pub(super) move_gas: u64,
    pub(super) duelists: Vec<CardDuelist>,
}

pub(super) fn parse_card_duel_request(config: &Value) -> Result<Option<CardDuelRequest>> {
    let Some(raw) = config.get("cardDuel") else {
        return Ok(None);
    };
    let object = raw.as_object().context("cardDuel must be an object")?;
    let entry_stake = parse_word(
        object
            .get("entryStake")
            .context("cardDuel.entryStake is required")?,
        "cardDuel.entryStake",
    )?;
    if entry_stake.is_zero() {
        bail!("cardDuel.entryStake must be positive");
    }
    let funded_amount = match object.get("fundedAmount") {
        None => entry_stake,
        Some(value) => parse_word(value, "cardDuel.fundedAmount")?,
    };
    if funded_amount < entry_stake {
        bail!("cardDuel.fundedAmount must cover cardDuel.entryStake");
    }
    let session_expiry = parse_u64_or(raw, "sessionExpiry", 2_000_000_000)?;
    let register_gas = parse_u64_or(raw, "registerGasLimit", DEFAULT_REGISTER_GAS)?;
    let move_gas = parse_u64_or(raw, "moveGasLimit", DEFAULT_MOVE_GAS)?;
    let duelists = parse_duelists(object.get("duelists"))?;
    Ok(Some(CardDuelRequest {
        entry_stake,
        funded_amount,
        session_expiry,
        register_gas,
        move_gas,
        duelists,
    }))
}

fn parse_duelists(raw: Option<&Value>) -> Result<Vec<CardDuelist>> {
    let Some(raw) = raw else {
        return Ok((0..CARD_ROOM_PLAYERS as u64)
            .map(|seat| CardDuelist {
                index: seat,
                signer_index: seat,
                session_key: None,
            })
            .collect());
    };
    let entries = raw.as_array().context("cardDuel.duelists must be an array")?;
    if entries.len() != CARD_ROOM_PLAYERS {
        bail!("cardDuel.duelists must name exactly {CARD_ROOM_PLAYERS} seats");
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for (seat, entry) in entries.iter().enumerate() {
        let object = entry
            .as_object()
            .with_context(|| format!("cardDuel.duelists[{seat}] must be an object"))?;
        let index = match object.get("index") {
            None => seat as u64,
            Some(value) => parse_u64_value(value, &format!("cardDuel.duelists[{seat}].index"))?,
        };
        let signer_index = match object.get("signerIndex") {
            None => seat as u64,
            Some(value) => {
                parse_u64_value(value, &format!("cardDuel.duelists[{seat}].signerIndex"))?
            }
        };
        let session_key = match object.get("sessionKey") {
            None => None,
            Some(value) => Some(parse_address_value(
                value,
                &format!("cardDuel.duelists[{seat}].sessionKey"),
            )?),
        };
        parsed.push(CardDuelist {
            index,
            signer_index,
            session_key,
        });
    }
    if parsed[0].index == parsed[1].index || parsed[0].signer_index == parsed[1].signer_index {
        bail!(
            "cardDuel.duelists must name distinct participant indices and distinct signers: \
             joinDuel rejects a second seat whose owner is the first seat's owner"
        );
    }
    Ok(parsed)
}

/// A `MerkleParticipants.Participant` leaf.
#[derive(Clone, Copy, Debug)]
struct Participant {
    index: u64,
    owner: Address,
    session_key: Address,
    session_expiry: u64,
    spend_limit: U256,
    payment_spent: U256,
    item_balance: U256,
    nonce: u64,
    application_data: B256,
}

impl Participant {
    /// `MerkleParticipants.participantHash` for an active participant.
    fn leaf(&self) -> B256 {
        keccak256(self.words().concat())
    }

    fn words(&self) -> [[u8; 32]; 10] {
        [
            word_u64(self.index),
            word_address(self.owner),
            word_address(self.session_key),
            word_u64(self.session_expiry),
            word_u256(self.spend_limit),
            word_u256(self.payment_spent),
            word_u256(self.item_balance),
            word_u64(self.nonce),
            self.application_data.0,
            word_u64(1),
        ]
    }
}

fn word_u64(value: u64) -> [u8; 32] {
    U256::from(value).to_be_bytes()
}

fn word_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

fn word_address(value: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(value.as_slice());
    word
}

fn selector(signature: &str) -> [u8; 4] {
    <[u8; 4]>::try_from(&keccak256(signature.as_bytes())[..4]).expect("keccak is 32 bytes")
}

pub(super) fn register_selector() -> [u8; 4] {
    selector("registerDuelist(uint64,address,uint64,uint256,bytes32[])")
}

pub(super) fn open_selector() -> [u8; 4] {
    selector(&format!("openDuel({PARTICIPANT_TUPLE},bytes32[])"))
}

pub(super) fn join_selector() -> [u8; 4] {
    selector(&format!("joinDuel({PARTICIPANT_TUPLE},bytes32[],uint64)"))
}

fn append_proof(calldata: &mut Vec<u8>, proof: &[B256]) {
    calldata.extend_from_slice(&word_u64(proof.len() as u64));
    for sibling in proof {
        calldata.extend_from_slice(sibling.as_slice());
    }
}

fn register_calldata(duelist: &CardDuelist, request: &CardDuelRequest, proof: &[B256]) -> Bytes {
    let mut calldata = register_selector().to_vec();
    calldata.extend_from_slice(&word_u64(duelist.index));
    calldata.extend_from_slice(&word_address(session_key_of(duelist)));
    calldata.extend_from_slice(&word_u64(request.session_expiry));
    calldata.extend_from_slice(&word_u256(request.funded_amount));
    // Four static head words precede the `bytes32[]` offset.
    calldata.extend_from_slice(&word_u64(0xa0));
    append_proof(&mut calldata, proof);
    Bytes::from(calldata)
}

fn open_calldata(participant: &Participant, proof: &[B256]) -> Bytes {
    let mut calldata = open_selector().to_vec();
    calldata.extend_from_slice(&participant.words().concat());
    // Ten inlined tuple words precede the `bytes32[]` offset.
    calldata.extend_from_slice(&word_u64(0x160));
    append_proof(&mut calldata, proof);
    Bytes::from(calldata)
}

fn join_calldata(participant: &Participant, proof: &[B256], duel_id: u64) -> Bytes {
    let mut calldata = join_selector().to_vec();
    calldata.extend_from_slice(&participant.words().concat());
    // Ten tuple words plus the trailing `uint64` precede the array data.
    calldata.extend_from_slice(&word_u64(0x180));
    calldata.extend_from_slice(&word_u64(duel_id));
    append_proof(&mut calldata, proof);
    Bytes::from(calldata)
}

/// `keccak256(abi.encode("CARD_OPEN", duelId, index))`, the `applicationData`
/// `CardDuelBase.openDuel` writes into the opener's replacement leaf.
fn open_application_data(duel_id: u64, index: u64) -> B256 {
    let mut encoded = Vec::with_capacity(160);
    encoded.extend_from_slice(&word_u64(0x60));
    encoded.extend_from_slice(&word_u64(duel_id));
    encoded.extend_from_slice(&word_u64(index));
    encoded.extend_from_slice(&word_u64(b"CARD_OPEN".len() as u64));
    let mut tail = [0u8; 32];
    tail[..9].copy_from_slice(b"CARD_OPEN");
    encoded.extend_from_slice(&tail);
    keccak256(encoded)
}

fn session_key_of(duelist: &CardDuelist) -> Address {
    duelist
        .session_key
        .unwrap_or_else(|| signer_address(duelist.signer_index))
}

/// The two blocks a duel room opens with, and the fixture EOAs that signed
/// them.
pub(super) struct CardDuelPlan {
    pub(super) first: Vec<Bytes>,
    pub(super) second: Vec<Bytes>,
    pub(super) owners: Vec<Address>,
    /// `(target, selector)` pairs the plan calls, for the policy cross-check.
    pub(super) calls: Vec<(Address, [u8; 4])>,
}

/// Build the duel-opening batch and advance `levels` to match the participant
/// root each call leaves behind.
pub(super) fn build_card_duel(
    chain_id: u64,
    duel: Address,
    capacity: u64,
    request: &CardDuelRequest,
    levels: &mut Vec<Vec<B256>>,
) -> Result<CardDuelPlan> {
    for duelist in &request.duelists {
        if duelist.index >= capacity {
            bail!(
                "cardDuel.duelists index {} is outside the participant capacity {capacity}",
                duelist.index
            );
        }
    }
    let mut first = Vec::with_capacity(CARD_ROOM_PLAYERS);
    let mut seated = Vec::with_capacity(CARD_ROOM_PLAYERS);
    let mut owners = Vec::with_capacity(CARD_ROOM_PLAYERS);
    for duelist in &request.duelists {
        let position = usize::try_from(duelist.index).expect("participant index fits usize");
        let proof = participant_proof(levels, position);
        let calldata = register_calldata(duelist, request, &proof);
        first.push(sign_calldata_as(
            chain_id,
            duelist.signer_index,
            0,
            duel,
            calldata,
            request.register_gas,
        ));
        let owner = signer_address(duelist.signer_index);
        owners.push(owner);
        let participant = Participant {
            index: duelist.index,
            owner,
            session_key: session_key_of(duelist),
            session_expiry: request.session_expiry,
            spend_limit: request.funded_amount,
            payment_spent: U256::ZERO,
            item_balance: U256::ZERO,
            nonce: 0,
            application_data: B256::ZERO,
        };
        update_participant_tree(levels, position, participant.leaf());
        seated.push(participant);
    }

    // Block two opens the duel and seats the opponent. `duelCount` starts at
    // zero in the cold state, so `openDuel` mints duel id one.
    let duel_id = 1u64;
    let opener = seated[0];
    let opener_position = usize::try_from(opener.index).expect("participant index fits usize");
    let opener_proof = participant_proof(levels, opener_position);
    let mut second = Vec::with_capacity(CARD_ROOM_PLAYERS);
    second.push(sign_calldata_as(
        chain_id,
        request.duelists[0].signer_index,
        1,
        duel,
        open_calldata(&opener, &opener_proof),
        request.move_gas,
    ));
    // `CardDuelBase._stake` charges the entry stake and bumps the nonce; the
    // opener's leaf therefore changes before the opponent's proof is built.
    let mut staked = opener;
    staked.payment_spent = opener.payment_spent + request.entry_stake;
    staked.nonce = opener.nonce + 1;
    staked.application_data = open_application_data(duel_id, opener.index);
    update_participant_tree(levels, opener_position, staked.leaf());

    let joiner = seated[1];
    let joiner_position = usize::try_from(joiner.index).expect("participant index fits usize");
    let joiner_proof = participant_proof(levels, joiner_position);
    second.push(sign_calldata_as(
        chain_id,
        request.duelists[1].signer_index,
        1,
        duel,
        join_calldata(&joiner, &joiner_proof, duel_id),
        request.move_gas,
    ));

    Ok(CardDuelPlan {
        first,
        second,
        owners,
        calls: vec![
            (duel, register_selector()),
            (duel, open_selector()),
            (duel, join_selector()),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_application_data_matches_solidity_abi_encoding() {
        // `cast abi-encode "f(string,uint64,uint64)" CARD_OPEN 1 0`
        let expected = concat!(
            "0000000000000000000000000000000000000000000000000000000000000060",
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000009",
            "434152445f4f50454e0000000000000000000000000000000000000000000000",
        );
        let encoded = alloy_primitives::hex::decode(expected).expect("fixed vector");
        assert_eq!(open_application_data(1, 0), keccak256(encoded));
    }

    #[test]
    fn entry_point_selectors_match_the_deployed_abi() {
        // `cast sig "registerDuelist(uint64,address,uint64,uint256,bytes32[])"`
        assert_eq!(register_selector(), [0xe2, 0x2b, 0x07, 0xa8]);
        assert_eq!(open_selector(), [0xf2, 0x70, 0x59, 0x75]);
        assert_eq!(join_selector(), [0x3e, 0x2a, 0x74, 0x17]);
    }

    #[test]
    fn register_calldata_is_abi_encoded() {
        let duelist = CardDuelist {
            index: 3,
            signer_index: 1,
            session_key: Some(Address::repeat_byte(0x11)),
        };
        let request = CardDuelRequest {
            entry_stake: U256::from(5),
            funded_amount: U256::from(9),
            session_expiry: 77,
            register_gas: 1,
            move_gas: 1,
            duelists: vec![],
        };
        let proof = [B256::repeat_byte(0xaa), B256::repeat_byte(0xbb)];
        let calldata = register_calldata(&duelist, &request, &proof);
        assert_eq!(calldata.len(), 4 + 5 * 32 + 32 + 2 * 32);
        assert_eq!(&calldata[..4], register_selector());
        assert_eq!(U256::from_be_slice(&calldata[4..36]), U256::from(3));
        assert_eq!(
            Address::from_slice(&calldata[48..68]),
            Address::repeat_byte(0x11)
        );
        assert_eq!(U256::from_be_slice(&calldata[68..100]), U256::from(77));
        assert_eq!(U256::from_be_slice(&calldata[100..132]), U256::from(9));
        assert_eq!(U256::from_be_slice(&calldata[132..164]), U256::from(0xa0));
        assert_eq!(U256::from_be_slice(&calldata[164..196]), U256::from(2));
    }
}
