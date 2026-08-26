//! Client-signed room transactions.
//!
//! `rawTransactions` is how a room accepts moves that were built and signed
//! somewhere the host has no key for -- a browser playing a hidden-card duel,
//! for instance. The host never forges those signatures, so it also never
//! learns anything about the player: an EIP-2718 envelope carries the public
//! calldata and a signature, nothing else.
//!
//! What the host still owes the room is a straight answer about what it was
//! handed. Passing opaque bytes through to the executor works, but every
//! mistake then surfaces as a native execution failure deep inside
//! `execute_batch_v5` with no address, no selector and no way to tell a
//! wrong-chain signature from an unfunded sender. So each envelope is decoded
//! once, here, and checked against the same admission policy `stf-core`'s
//! `tx_env_from_raw` enforces plus the two rules a *room* adds: a room
//! transaction always calls an existing contract (rooms forbid contract
//! creation) and always carries a four-byte selector, because the certified
//! `callRules` are expressed in selectors.
//!
//! The decode is what lets a client-signed batch keep everything a
//! host-scripted one has: the recovered senders become the accounts the opening
//! state must seat, and the recovered `(target, selector)` pairs feed the same
//! `callRules` cross-check the card plan goes through.

use alloy_consensus::{transaction::SignerRecoverable, Transaction, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, Bytes, TxKind};
use anyhow::{bail, Context, Result};

/// One decoded client-signed transaction, reduced to what the room needs to
/// know about it. The calldata itself is never retained or logged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ClientTransaction {
    pub(super) sender: Address,
    pub(super) target: Address,
    pub(super) selector: [u8; 4],
}

/// Decode and admission-check every client-signed envelope in the batch.
///
/// `chain_id` is the room chain id. A transaction signed for another chain is
/// refused here rather than inside revm so the caller is told which chain it
/// used; a room whose id the client guessed wrong is the single most likely
/// integration mistake and the most expensive one to debug from a proof.
pub(super) fn inspect_client_transactions(
    blocks: &[Vec<Bytes>],
    chain_id: u64,
) -> Result<Vec<ClientTransaction>> {
    let mut inspected = Vec::new();
    for (block_index, block) in blocks.iter().enumerate() {
        for (index, raw) in block.iter().enumerate() {
            let label = format!("rawTransactions[{block_index}][{index}]");
            inspected.push(
                inspect_one(raw, chain_id)
                    .with_context(|| format!("{label} is not an admissible room transaction"))?,
            );
        }
    }
    Ok(inspected)
}

fn inspect_one(raw: &Bytes, chain_id: u64) -> Result<ClientTransaction> {
    // EIP-2718 type bytes are unambiguous, and `stf-core` rejects blob (0x03)
    // and EIP-7702 (0x04) envelopes outright. Naming them before the decode
    // keeps a truncated adversarial payload from failing as generic RLP.
    if matches!(raw.first(), Some(0x03 | 0x04)) {
        bail!(
            "envelope type 0x{:02x} is outside the room transaction profile; a room admits \
             legacy, EIP-2930 and EIP-1559 transactions only",
            raw[0]
        );
    }
    let envelope = TxEnvelope::decode_2718(&mut &raw[..])
        .map_err(|error| anyhow::anyhow!("decode EIP-2718 envelope: {error}"))?;
    match &envelope {
        TxEnvelope::Legacy(_) | TxEnvelope::Eip2930(_) | TxEnvelope::Eip1559(_) => {}
        other => bail!(
            "envelope type {} is outside the room transaction profile",
            other.tx_type() as u8
        ),
    }
    if envelope.nonce() == u64::MAX {
        bail!("transaction nonce cannot equal the uint64 maximum");
    }
    // Free-gas L2. `tx_env_from_raw` rejects fee-bearing transactions, so an
    // accepted one would fail natively after the whole batch had been built.
    if envelope.max_fee_per_gas() != 0 {
        bail!(
            "a room runs on free gas, but this transaction pays {}",
            envelope.max_fee_per_gas()
        );
    }
    if envelope.max_priority_fee_per_gas().unwrap_or(0) != 0 {
        bail!(
            "a room runs on free gas, but this transaction tips {}",
            envelope.max_priority_fee_per_gas().unwrap_or(0)
        );
    }
    match envelope.chain_id() {
        None => bail!(
            "a pre-EIP-155 transaction carries no chain id and replays across chains; this room \
             is chain {chain_id}"
        ),
        Some(id) if id != chain_id => bail!(
            "transaction is signed for chain {id}, but this room is chain {chain_id}"
        ),
        Some(_) => {}
    }
    let target = match envelope.kind() {
        TxKind::Call(target) => target,
        // `ExecutionPolicyV5.allow_contract_creation` is false for every
        // fixture room, so a CREATE would be refused by the guest anyway --
        // but it has no target and therefore no call rule to check.
        TxKind::Create => bail!(
            "a room transaction calls one of the room's contracts; contract creation is outside \
             the certified policy"
        ),
    };
    let input = envelope.input();
    if input.len() < 4 {
        bail!(
            "a room transaction carries a four-byte selector, but this one has {} bytes of \
             calldata; the certified callRules are expressed in selectors",
            input.len()
        );
    }
    let selector = <[u8; 4]>::try_from(&input[..4]).expect("four bytes were just checked");
    let sender = envelope
        .recover_signer()
        .map_err(|error| anyhow::anyhow!("recover signer: {error}"))?;
    Ok(ClientTransaction {
        sender,
        target,
        selector,
    })
}

/// Refuse a batch signed by an account the room's opening state never seats.
///
/// Such a sender has no nonce, no balance and no entry in the compact witness,
/// so the batch fails as `UndeclaredAccount` deep inside `execute_batch_v5`
/// with nothing naming the key at fault. `signers` is the room's own signer
/// accounts plus everything `senderAccounts` declared.
pub(super) fn check_senders_are_seated(
    transactions: &[ClientTransaction],
    signers: &[Address],
) -> Result<()> {
    for transaction in transactions {
        if !signers.contains(&transaction.sender) {
            bail!(
                "a rawTransactions entry is signed by {}, which this room does not seat; name it \
                 in `senderAccounts` (and raise `residentAccounts` to cover it) or sign with one \
                 of the room's own signer accounts",
                transaction.sender
            );
        }
    }
    Ok(())
}

/// The distinct accounts that signed the batch, in first-seen order.
pub(super) fn client_senders(transactions: &[ClientTransaction]) -> Vec<Address> {
    let mut senders: Vec<Address> = Vec::new();
    for transaction in transactions {
        if !senders.contains(&transaction.sender) {
            senders.push(transaction.sender);
        }
    }
    senders
}

/// The distinct `(target, selector)` pairs the batch calls, for the same
/// `callRules` cross-check a host-scripted plan goes through.
pub(super) fn client_calls(transactions: &[ClientTransaction]) -> Vec<(Address, [u8; 4])> {
    let mut calls: Vec<(Address, [u8; 4])> = Vec::new();
    for transaction in transactions {
        let call = (transaction.target, transaction.selector);
        if !calls.contains(&call) {
            calls.push(call);
        }
    }
    calls
}

/// The selectors the batch uses, sorted and deduplicated, for the flat
/// allow-list a room without `callRules` certifies.
pub(super) fn client_selectors(transactions: &[ClientTransaction]) -> Vec<[u8; 4]> {
    let mut selectors = transactions
        .iter()
        .map(|transaction| transaction.selector)
        .collect::<Vec<_>>();
    selectors.sort();
    selectors.dedup();
    selectors
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v5_fixture::signing::{sign_calldata_as, sign_transaction, signer_address};
    use alloy_consensus::TxEip1559;
    use alloy_primitives::U256;

    const CHAIN: u64 = 424_242;
    const TARGET: Address = Address::repeat_byte(0xd1);

    fn calldata(selector: [u8; 4]) -> Bytes {
        let mut input = selector.to_vec();
        input.extend_from_slice(&[0u8; 32]);
        Bytes::from(input)
    }

    fn eip1559(chain_id: u64) -> TxEip1559 {
        TxEip1559 {
            chain_id,
            nonce: 0,
            gas_limit: 120_000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(TARGET),
            value: U256::ZERO,
            access_list: Default::default(),
            input: calldata([0x12, 0x34, 0x56, 0x78]),
        }
    }

    #[test]
    fn a_signed_batch_yields_its_senders_targets_and_selectors() {
        let first = sign_calldata_as(CHAIN, 0, 0, TARGET, calldata([0xaa; 4]), 120_000);
        let second = sign_calldata_as(CHAIN, 1, 0, TARGET, calldata([0xbb; 4]), 120_000);
        let inspected =
            inspect_client_transactions(&[vec![first], vec![second]], CHAIN).expect("admissible");
        assert_eq!(inspected.len(), 2);
        assert_eq!(inspected[0].sender, signer_address(0));
        assert_eq!(inspected[1].sender, signer_address(1));
        assert_eq!(inspected[0].target, TARGET);
        assert_eq!(inspected[0].selector, [0xaa; 4]);
        assert_eq!(client_senders(&inspected), vec![signer_address(0), signer_address(1)]);
        assert_eq!(
            client_calls(&inspected),
            vec![(TARGET, [0xaa; 4]), (TARGET, [0xbb; 4])]
        );
        assert_eq!(client_selectors(&inspected), vec![[0xaa; 4], [0xbb; 4]]);
    }

    #[test]
    fn repeated_senders_and_calls_are_reported_once() {
        let first = sign_calldata_as(CHAIN, 0, 0, TARGET, calldata([0xaa; 4]), 120_000);
        let second = sign_calldata_as(CHAIN, 0, 1, TARGET, calldata([0xaa; 4]), 120_000);
        let inspected =
            inspect_client_transactions(&[vec![first], vec![second]], CHAIN).expect("admissible");
        assert_eq!(client_senders(&inspected), vec![signer_address(0)]);
        assert_eq!(client_calls(&inspected), vec![(TARGET, [0xaa; 4])]);
        assert_eq!(client_selectors(&inspected), vec![[0xaa; 4]]);
    }

    #[test]
    fn a_transaction_signed_for_another_chain_is_refused() {
        let stray = sign_calldata_as(CHAIN + 1, 0, 0, TARGET, calldata([0xaa; 4]), 120_000);
        let error = inspect_client_transactions(&[vec![stray], vec![]], CHAIN)
            .expect_err("a room never proves another chain's transaction");
        let error = format!("{error:#}");
        assert!(error.contains("signed for chain"), "{error}");
        assert!(error.contains("rawTransactions[0][0]"), "{error}");
    }

    #[test]
    fn a_contract_creation_is_not_a_room_transaction() {
        let mut tx = eip1559(CHAIN);
        tx.to = TxKind::Create;
        let raw = sign_transaction(tx, 0);
        let error = inspect_client_transactions(&[vec![raw], vec![]], CHAIN)
            .expect_err("rooms forbid contract creation");
        assert!(format!("{error:#}").contains("contract creation"), "{error:#}");
    }

    #[test]
    fn a_transaction_without_a_selector_is_refused() {
        let mut tx = eip1559(CHAIN);
        tx.input = Bytes::from_static(&[0x12, 0x34, 0x56]);
        let raw = sign_transaction(tx, 0);
        let error = inspect_client_transactions(&[vec![raw], vec![]], CHAIN)
            .expect_err("callRules are expressed in selectors");
        assert!(format!("{error:#}").contains("four-byte selector"), "{error:#}");
    }

    #[test]
    fn a_fee_bearing_transaction_is_refused() {
        let mut tx = eip1559(CHAIN);
        tx.max_fee_per_gas = 1;
        let raw = sign_transaction(tx, 0);
        let error = inspect_client_transactions(&[vec![raw], vec![]], CHAIN)
            .expect_err("a room runs on free gas");
        assert!(format!("{error:#}").contains("free gas"), "{error:#}");

        let mut tipped = eip1559(CHAIN);
        tipped.max_priority_fee_per_gas = 1;
        let raw = sign_transaction(tipped, 0);
        let error = inspect_client_transactions(&[vec![raw], vec![]], CHAIN)
            .expect_err("a room runs on free gas");
        assert!(format!("{error:#}").contains("tips"), "{error:#}");
    }

    #[test]
    fn blob_and_authorization_envelopes_are_named_not_guessed() {
        for kind in [0x03u8, 0x04u8] {
            let raw = Bytes::from(vec![kind; 64]);
            let error = inspect_client_transactions(&[vec![raw], vec![]], CHAIN)
                .expect_err("outside the room transaction profile");
            let error = format!("{error:#}");
            assert!(error.contains("outside the room transaction profile"), "{error}");
            assert!(error.contains(&format!("0x{kind:02x}")), "{error}");
        }
    }

    #[test]
    fn bytes_that_are_not_a_transaction_are_refused_before_execution() {
        let raw = Bytes::from(vec![0x99; 48]);
        let error = inspect_client_transactions(&[vec![raw], vec![]], CHAIN)
            .expect_err("garbage is not a signed transaction");
        assert!(format!("{error:#}").contains("decode EIP-2718 envelope"), "{error:#}");
    }
}
