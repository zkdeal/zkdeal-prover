//! Production live-room batch preparation.
//!
//! This is deliberately separate from `v5_fixture`: callers supply a complete
//! live prestate, the exact blocks produced by the room engine, and a snapshot
//! of the corresponding `RoomManager` opening facts.  The host derives every
//! journal commitment and cursor transition, executes the current STF
//! natively, and returns the content-addressed witness consumed by
//! `/v5/rooms/prove`.

use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde::Deserialize;
use stf_types::{
    admission_records_hash_v5, batch_block_data_hash_v5, canonical_batch_data_v5,
    execution_policy_hash_v5, forced_outcomes_hash_v5, hash_batch_journal_v5,
    import_root_v5, inbox_records_hash_v5, liabilities_hash_v5, roster_changes_hash_v5,
    withdrawal_root_v5, AdmissionRecordV5, AssetLiabilityV5, BatchBlockV5,
    BatchInputV5, BatchJournalV5, CompactStateWitnessV4, DepositV5, ExecutionPolicyV5,
    ForcedTransactionV5, L1ImportWitnessV5, RosterChangeV5, RosterMemberV5, WithdrawalV5,
    BATCH_JOURNAL_VERSION_V6,
};

use crate::receipt::image_id_hex;
use crate::witness::room_witness_from_stdin;
use crate::B64;

const LIVE_PREPARE_SCHEMA_V1: u8 = 1;
const ROOM_STATE_OPEN: u8 = 1;
const ROOM_STATE_CLOSED: u8 = 2;
const VALIDITY_ONLY: u8 = 1;
const ADMISSION_RECEIPT_TYPE: &[u8] = b"AdmissionReceipt(uint64 roomId,uint64 admissionId,bytes32 transactionHash,uint64 depositInboxId,bytes32 depositContentHash,uint64 deadlineBlock,uint64 maximumBatchIndex,uint64 bondEpoch,uint256 admissionFee)";

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveOpeningV1 {
    room_state: u8,
    deployment_domain: B256,
    eip712_domain_separator: B256,
    room_id: u64,
    authorization_mode: u8,
    cold_template_id: B256,
    proof_program_id: B256,
    proof_system_version: B256,
    policy_hash: B256,
    state_root: B256,
    participant_root: B256,
    participant_epoch: u64,
    participant_count: u64,
    participant_capacity: u64,
    approver_root: B256,
    approver_epoch: u64,
    active_count: u64,
    batch_index: u64,
    l2_block_height: u64,
    approver_change_cursor: u64,
    inbox_cursor: u64,
    admission_cursor: u64,
    forced_cursor: u64,
    import_cursor: u64,
    outbox_epoch: u64,
    maximum_admission_window: u64,
    bond_epoch: u64,
    admission_signer: Address,
    minimum_service_bond: U256,
    service_bond: U256,
    liabilities_hash: B256,
    observed_l1_block: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveClosingV1 {
    participant_root: B256,
    participant_epoch: u64,
    participant_count: u64,
    l1_inclusion_deadline: u64,
    #[serde(default)]
    close: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveBatchPrepareRequestV1 {
    schema_version: u8,
    production: bool,
    proof_mode: String,
    l1_chain_id: u64,
    /// A terminal batch chains onto the last accepted state of a
    /// recovery-closed room and must close it; ordinary preparation keeps
    /// requiring an open room.
    #[serde(default)]
    terminal: bool,
    opening: LiveOpeningV1,
    closing: LiveClosingV1,
    policy: ExecutionPolicyV5,
    approver_capacity: u64,
    #[serde(default)]
    pre_approvers: Vec<RosterMemberV5>,
    #[serde(default)]
    post_approvers: Vec<RosterMemberV5>,
    #[serde(default)]
    approver_changes: Vec<RosterChangeV5>,
    #[serde(default)]
    admissions: Vec<AdmissionRecordV5>,
    #[serde(default)]
    forced_transactions: Vec<ForcedTransactionV5>,
    #[serde(default)]
    pre_liabilities: Vec<AssetLiabilityV5>,
    #[serde(default)]
    post_liabilities: Vec<AssetLiabilityV5>,
    #[serde(default)]
    deposits: Vec<DepositV5>,
    #[serde(default)]
    withdrawals: Vec<WithdrawalV5>,
    withdrawal_capacity: u64,
    #[serde(default)]
    l1_import: Option<L1ImportWitnessV5>,
    compact_state: CompactStateWitnessV4,
    blocks: Vec<BatchBlockV5>,
}

fn checked_advance(value: u64, count: usize, label: &str) -> Result<u64> {
    value
        .checked_add(u64::try_from(count).context("batch item count exceeds u64")?)
        .with_context(|| format!("{label} overflow"))
}

fn abi_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn abi_u256(value: U256) -> [u8; 32] {
    value.to_be_bytes::<32>()
}

fn keccak_words(words: impl IntoIterator<Item = [u8; 32]>) -> B256 {
    let words = words.into_iter().collect::<Vec<_>>();
    let mut encoded = Vec::with_capacity(words.len() * 32);
    for word in words {
        encoded.extend_from_slice(&word);
    }
    keccak256(encoded)
}

fn admission_receipt_struct_hash(room_id: u64, record: &AdmissionRecordV5) -> B256 {
    keccak_words([
        keccak256(ADMISSION_RECEIPT_TYPE).0,
        abi_u64(room_id),
        abi_u64(record.receipt.admission_id),
        record.receipt.transaction_hash.0,
        abi_u64(record.receipt.deposit_inbox_id),
        record.receipt.deposit_content_hash.0,
        abi_u64(record.receipt.deadline_block),
        abi_u64(record.receipt.maximum_batch_index),
        abi_u64(record.receipt.bond_epoch),
        abi_u256(record.receipt.admission_fee),
    ])
}

fn recover_address(digest: B256, signature: &Bytes) -> Result<Address> {
    let bytes = signature.as_ref();
    if bytes.len() != 65 {
        bail!("admission receipt signature must be exactly 65 bytes");
    }
    let signature = Signature::from_slice(&bytes[..64]).context("admission ECDSA signature")?;
    if signature.normalize_s().is_some() {
        bail!("admission receipt signature is not low-s canonical");
    }
    let v = match bytes[64] {
        0 | 1 => bytes[64],
        27 | 28 => bytes[64] - 27,
        _ => bail!("admission receipt recovery id is not 0/1/27/28"),
    };
    let recovery = RecoveryId::try_from(v).context("admission recovery id")?;
    let key = VerifyingKey::recover_from_prehash(digest.as_slice(), &signature, recovery)
        .context("recover admission signer")?;
    let encoded = key.to_encoded_point(false);
    Ok(Address::from_slice(&keccak256(&encoded.as_bytes()[1..]).as_slice()[12..]))
}

fn validate_admission_envelopes(request: &LiveBatchPrepareRequestV1, batch_index: u64) -> Result<()> {
    if request.admissions.is_empty() {
        return Ok(());
    }
    let opening = &request.opening;
    if opening.admission_signer == Address::ZERO
        || opening.eip712_domain_separator == B256::ZERO
        || opening.maximum_admission_window == 0
        || opening.service_bond < opening.minimum_service_bond
    {
        bail!("live admission opening facts do not satisfy the on-chain service boundary");
    }
    let latest_deadline = opening
        .observed_l1_block
        .checked_add(opening.maximum_admission_window)
        .context("maximum admission deadline overflow")?;
    for record in &request.admissions {
        if record.receipt.bond_epoch != opening.bond_epoch
            || record.receipt.maximum_batch_index < batch_index
            || record.receipt.deadline_block < request.closing.l1_inclusion_deadline
            || record.receipt.deadline_block > latest_deadline
        {
            bail!("admission receipt is outside the live room bond, batch or deadline facts");
        }
        let struct_hash = admission_receipt_struct_hash(opening.room_id, record);
        let mut typed = Vec::with_capacity(66);
        typed.extend_from_slice(b"\x19\x01");
        typed.extend_from_slice(opening.eip712_domain_separator.as_slice());
        typed.extend_from_slice(struct_hash.as_slice());
        if recover_address(keccak256(typed), &record.receipt.signature)?
            != opening.admission_signer
        {
            bail!("admission receipt is not signed by the live room admission signer");
        }
    }
    Ok(())
}

fn solidity_journal(journal: &BatchJournalV5) -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": journal.protocol_version,
        "deploymentDomain": journal.deployment_domain,
        "roomId": journal.room_id,
        "authorizationMode": journal.authorization_mode,
        "coldTemplateId": journal.cold_template_id,
        "proofProgramId": journal.proof_program_id,
        "proofSystemVersion": journal.proof_system_version,
        "policyHash": journal.policy_hash,
        "batchIndex": journal.batch_index,
        "startL2Block": journal.start_l2_block,
        "endL2Block": journal.end_l2_block,
        "preStateRoot": journal.pre_state_root,
        "postStateRoot": journal.post_state_root,
        "batchDataHash": journal.batch_data_hash,
        "canonicalDataHash": journal.canonical_data_hash,
        "preParticipantRoot": journal.pre_participant_root,
        "postParticipantRoot": journal.post_participant_root,
        "preParticipantEpoch": journal.pre_participant_epoch,
        "postParticipantEpoch": journal.post_participant_epoch,
        "preParticipantCount": journal.pre_participant_count,
        "postParticipantCount": journal.post_participant_count,
        "participantCapacity": journal.participant_capacity,
        "preApproverRoot": journal.pre_roster_root,
        "postApproverRoot": journal.post_roster_root,
        "preApproverEpoch": journal.pre_roster_epoch,
        "postApproverEpoch": journal.post_roster_epoch,
        "preActiveCount": journal.pre_active_count,
        "postActiveCount": journal.post_active_count,
        "approverChangeCursorBefore": journal.roster_change_cursor_before,
        "approverChangeCursorAfter": journal.roster_change_cursor_after,
        "inboxCursorBefore": journal.inbox_cursor_before,
        "inboxCursorAfter": journal.inbox_cursor_after,
        "inboxRecordsHash": journal.inbox_records_hash,
        "admissionCursorBefore": journal.admission_cursor_before,
        "admissionCursorAfter": journal.admission_cursor_after,
        "admissionRecordsHash": journal.admission_records_hash,
        "forcedCursorBefore": journal.forced_cursor_before,
        "forcedCursorAfter": journal.forced_cursor_after,
        "forcedOutcomesHash": journal.forced_outcomes_hash,
        "importCursorBefore": journal.import_cursor_before,
        "importCursorAfter": journal.import_cursor_after,
        "importedL1Block": journal.imported_l1_block,
        "importedL1HeaderHash": journal.imported_l1_header_hash,
        "importedL1StateRoot": journal.imported_l1_state_root,
        "importRoot": journal.import_root,
        "outboxEpoch": journal.outbox_epoch,
        "withdrawalRoot": journal.withdrawal_root,
        "preLiabilitiesHash": journal.pre_liabilities_hash,
        "postLiabilitiesHash": journal.post_liabilities_hash,
        "approverChangesHash": journal.roster_changes_hash,
        "l1InclusionDeadline": journal.l1_inclusion_deadline,
        "close": journal.close,
    })
}

fn solidity_admissions(records: &[AdmissionRecordV5]) -> Vec<serde_json::Value> {
    records
        .iter()
        .map(|record| serde_json::json!({
            "receipt": {
                "admissionId": record.receipt.admission_id,
                "transactionHash": record.receipt.transaction_hash,
                "depositInboxId": record.receipt.deposit_inbox_id,
                "depositContentHash": record.receipt.deposit_content_hash,
                "deadlineBlock": record.receipt.deadline_block,
                "maximumBatchIndex": record.receipt.maximum_batch_index,
                "bondEpoch": record.receipt.bond_epoch,
                "admissionFee": record.receipt.admission_fee,
                "signature": format!("0x{}", hex::encode(record.receipt.signature.as_ref())),
            },
            "outcome": {
                "admissionId": record.outcome.admission_id,
                "transactionHash": record.outcome.transaction_hash,
                "status": record.outcome.status,
                "l2BlockNumber": record.outcome.l2_block_number,
                "transactionIndex": record.outcome.transaction_index,
                "reasonHash": record.outcome.reason_hash,
            }
        }))
        .collect()
}

fn solidity_forced_outcomes(records: &[ForcedTransactionV5]) -> Vec<serde_json::Value> {
    records
        .iter()
        .map(|record| serde_json::json!({
            "forcedId": record.forced_id,
            "transactionHash": record.outcome.transaction_hash,
            "status": record.outcome.status,
            "l2BlockNumber": record.outcome.l2_block_number,
            "transactionIndex": record.outcome.transaction_index,
            "reasonHash": record.outcome.reason_hash,
        }))
        .collect()
}

fn solidity_liabilities(records: &[AssetLiabilityV5]) -> Vec<serde_json::Value> {
    records
        .iter()
        .map(|record| serde_json::json!({
            "asset": record.asset,
            "pending": record.pending,
            "controlled": record.controlled,
            "claimable": record.claimable,
            "paid": record.paid,
        }))
        .collect()
}

fn prepare_input(request: LiveBatchPrepareRequestV1) -> Result<BatchInputV5> {
    if request.schema_version != LIVE_PREPARE_SCHEMA_V1
        || !request.production
        || request.proof_mode != "groth16"
    {
        bail!("live prepare requires schemaVersion=1, production=true and proofMode=groth16");
    }
    let opening = &request.opening;
    if request.terminal && !request.closing.close {
        bail!("terminal live preparation requires a closing journal");
    }
    let required_room_state = if request.terminal {
        ROOM_STATE_CLOSED
    } else {
        ROOM_STATE_OPEN
    };
    if opening.room_state != required_room_state
        || opening.authorization_mode != VALIDITY_ONLY
        || opening.room_id == 0
        || opening.deployment_domain == B256::ZERO
        || opening.state_root == B256::ZERO
        || opening.participant_root == B256::ZERO
        || opening.participant_epoch == 0
        || opening.participant_capacity == 0
        || opening.proof_program_id == B256::ZERO
        || opening.proof_system_version == B256::ZERO
        || opening.policy_hash == B256::ZERO
    {
        bail!("live prepare opening facts are zero, in the wrong room state, or not VALIDITY_ONLY");
    }
    if request.blocks.is_empty() {
        bail!("live prepare requires at least one live engine block");
    }
    if execution_policy_hash_v5(&request.policy) != opening.policy_hash {
        bail!("live execution policy does not match the on-chain policyHash");
    }
    if liabilities_hash_v5(&request.pre_liabilities) != opening.liabilities_hash {
        bail!("live pre-liabilities do not match the on-chain liabilities hash");
    }
    if !request.pre_approvers.is_empty()
        || !request.post_approvers.is_empty()
        || !request.approver_changes.is_empty()
        || opening.approver_root != B256::ZERO
        || opening.active_count != 0
    {
        bail!("VALIDITY_ONLY live preparation cannot carry checkpoint approvers");
    }

    let batch_index = opening.batch_index.checked_add(1).context("batch index overflow")?;
    let start_l2_block = opening
        .l2_block_height
        .checked_add(1)
        .context("L2 block height overflow")?;
    let end_l2_block = checked_advance(start_l2_block, request.blocks.len() - 1, "L2 range")?;
    let post_state_root = request
        .blocks
        .last()
        .map(|block| block.expected_post_state_root)
        .context("live block list is empty")?;
    if request.blocks[0].block_number != start_l2_block
        || request.blocks.last().map(|block| block.block_number) != Some(end_l2_block)
        || post_state_root == B256::ZERO
    {
        bail!("live blocks do not continue the on-chain L2 height or omit a terminal root");
    }
    if request.closing.participant_root == B256::ZERO
        || request.closing.participant_epoch == 0
        || request.closing.participant_count > opening.participant_capacity
        || request.closing.l1_inclusion_deadline <= opening.observed_l1_block
    {
        bail!("live closing participant or inclusion-deadline facts are invalid");
    }
    validate_admission_envelopes(&request, batch_index)?;

    // `withdrawal_root_v5` short-circuits to the zero root for an empty leaf
    // list before it ever looks at the capacity, so a junk capacity would
    // otherwise only fail minutes later inside the guest's exit derivation.
    if request.withdrawal_capacity != 0 && request.withdrawals.is_empty() {
        bail!(
            "live prepare declares withdrawalCapacity {} but carries no withdrawals; a batch \
             without withdrawal leaves must declare capacity 0",
            request.withdrawal_capacity
        );
    }
    let canonical_batch_data = canonical_batch_data_v5(&request.blocks, opening.state_root);
    let l1_import = request.l1_import.as_ref();
    let withdrawal_root = withdrawal_root_v5(
        opening.deployment_domain,
        opening.room_id,
        opening.outbox_epoch.checked_add(1).context("outbox epoch overflow")?,
        &request.withdrawals,
        request.withdrawal_capacity,
    )
    .context("invalid live withdrawal positional tree")?;
    let journal = BatchJournalV5 {
        protocol_version: BATCH_JOURNAL_VERSION_V6,
        deployment_domain: opening.deployment_domain,
        room_id: opening.room_id,
        authorization_mode: opening.authorization_mode,
        cold_template_id: opening.cold_template_id,
        proof_program_id: opening.proof_program_id,
        proof_system_version: opening.proof_system_version,
        policy_hash: opening.policy_hash,
        batch_index,
        start_l2_block,
        end_l2_block,
        pre_state_root: opening.state_root,
        post_state_root,
        batch_data_hash: batch_block_data_hash_v5(&request.blocks, opening.state_root),
        canonical_data_hash: keccak256(&canonical_batch_data),
        pre_participant_root: opening.participant_root,
        post_participant_root: request.closing.participant_root,
        pre_participant_epoch: opening.participant_epoch,
        post_participant_epoch: request.closing.participant_epoch,
        pre_participant_count: opening.participant_count,
        post_participant_count: request.closing.participant_count,
        participant_capacity: opening.participant_capacity,
        pre_roster_root: B256::ZERO,
        post_roster_root: B256::ZERO,
        pre_roster_epoch: opening.approver_epoch,
        post_roster_epoch: opening.approver_epoch,
        pre_active_count: 0,
        post_active_count: 0,
        roster_change_cursor_before: opening.approver_change_cursor,
        roster_change_cursor_after: opening.approver_change_cursor,
        inbox_cursor_before: opening.inbox_cursor,
        inbox_cursor_after: checked_advance(opening.inbox_cursor, request.deposits.len(), "inbox cursor")?,
        inbox_records_hash: inbox_records_hash_v5(&request.deposits),
        admission_cursor_before: opening.admission_cursor,
        admission_cursor_after: checked_advance(opening.admission_cursor, request.admissions.len(), "admission cursor")?,
        admission_records_hash: admission_records_hash_v5(&request.admissions),
        forced_cursor_before: opening.forced_cursor,
        forced_cursor_after: checked_advance(opening.forced_cursor, request.forced_transactions.len(), "forced cursor")?,
        forced_outcomes_hash: forced_outcomes_hash_v5(&request.forced_transactions),
        import_cursor_before: opening.import_cursor,
        import_cursor_after: opening
            .import_cursor
            .checked_add(u64::from(l1_import.is_some()))
            .context("import cursor overflow")?,
        imported_l1_block: l1_import.map_or(0, |value| value.source_block),
        imported_l1_header_hash: l1_import.map_or(B256::ZERO, |value| value.header_hash),
        imported_l1_state_root: l1_import.map_or(B256::ZERO, |value| value.state_root),
        import_root: l1_import.map_or(B256::ZERO, |value| {
            import_root_v5(opening.room_id, request.l1_chain_id, value)
        }),
        outbox_epoch: opening.outbox_epoch.checked_add(1).context("outbox epoch overflow")?,
        withdrawal_root,
        pre_liabilities_hash: liabilities_hash_v5(&request.pre_liabilities),
        post_liabilities_hash: liabilities_hash_v5(&request.post_liabilities),
        roster_changes_hash: roster_changes_hash_v5(&[]),
        l1_inclusion_deadline: request.closing.l1_inclusion_deadline,
        close: request.closing.close,
    };
    Ok(BatchInputV5 {
        encoded_witness_bytes: 0,
        l1_chain_id: request.l1_chain_id,
        journal,
        policy: request.policy,
        roster_capacity: request.approver_capacity,
        pre_roster: request.pre_approvers,
        post_roster: request.post_approvers,
        roster_changes: request.approver_changes,
        admissions: request.admissions,
        forced_transactions: request.forced_transactions,
        canonical_batch_data: Bytes::from(canonical_batch_data),
        pre_liabilities: request.pre_liabilities,
        post_liabilities: request.post_liabilities,
        deposits: request.deposits,
        withdrawals: request.withdrawals,
        withdrawal_capacity: request.withdrawal_capacity,
        l1_import: request.l1_import,
        compact_state: request.compact_state,
        blocks: request.blocks,
    })
}

pub(crate) fn cmd_prepare_live_room_batch(raw: &str) -> Result<serde_json::Value> {
    let request: LiveBatchPrepareRequestV1 =
        serde_json::from_str(raw).context("live room prepare request is not schema-v1 JSON")?;
    let input = prepare_input(request)?;
    let outcome = stf_core::execute_batch_v5_with_report(&input)
        .map_err(|error| anyhow!("native live room preparation failed: {error}"))?;
    if outcome.journal != input.journal {
        bail!("native live room execution returned a different journal");
    }
    let proof_request = serde_json::json!({
        "roomWitness": input,
        "proofMode": "groth16",
        "production": true,
    });
    let proof_request_raw = serde_json::to_string(&proof_request)?;
    let (_validated, _request, witness, address) = room_witness_from_stdin(&proof_request_raw)?;
    let prepare_artifact_digest = address
        .input_digest
        .strip_prefix("0x")
        .context("room witness input digest is not canonical 0x-prefixed SHA-256")?;
    let journal_hash = hash_batch_journal_v5(&input.journal);
    let submission = serde_json::json!({
        "journal": solidity_journal(&input.journal),
        "seal": "0x",
        "canonicalBatchData": format!("0x{}", hex::encode(input.canonical_batch_data.as_ref())),
        "approvals": [],
        "approverChanges": [],
        "admissions": solidity_admissions(&input.admissions),
        "forcedOutcomes": solidity_forced_outcomes(&input.forced_transactions),
        "liabilities": solidity_liabilities(&input.post_liabilities),
    });
    Ok(serde_json::json!({
        "schemaVersion": LIVE_PREPARE_SCHEMA_V1,
        "preparedFrom": "live-room-engine-state",
        "fixture": false,
        "programId": format!("0x{}", image_id_hex()),
        "journal": input.journal,
        "journalHash": format!("0x{}", hex::encode(journal_hash)),
        "prepareArtifactDigest": prepare_artifact_digest,
        "contentAddress": prepare_artifact_digest,
        "proverJobIdentity": address.job_id,
        "roomWitnessB64": B64.encode(&witness),
        "proofRequest": {
            "roomWitnessB64": B64.encode(&witness),
            "inputDigest": address.input_digest,
            "jobId": address.job_id,
            "proofMode": "groth16",
            "production": true,
        },
        "provisionalSubmission": submission,
        "proofWork": {
            "blockCount": outcome.proof_work.block_count,
            "encodedWitnessBytes": witness.len(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use stf_types::{AdmissionOutcomeV5, AdmissionReceiptV5};

    fn fixture_live_request() -> serde_json::Value {
        let image = crate::witness::embedded_program_id_v5();
        let prepared = crate::v5_fixture::prepare(
            r#"{
                "schemaVersion": 1,
                "production": true,
                "roomId": 91,
                "deploymentDomain": "0x1111111111111111111111111111111111111111111111111111111111111111",
                "authorizationMode": "validity-only",
                "activeSigners": 0,
                "workload": "storage",
                "stateCommitment": "mpt",
                "l1InclusionDeadline": 100,
                "l1ChainId": 31337,
                "participantCapacity": 128,
                "registeredParticipants": 2,
                "blocks": 2
            }"#,
            image,
        )
        .expect("fixture prepares a valid current witness");
        let input: BatchInputV5 = serde_json::from_value(
            prepared["roomRequest"]["roomWitness"].clone(),
        )
        .expect("fixture room witness decodes");
        serde_json::json!({
            "schemaVersion": 1,
            "production": true,
            "proofMode": "groth16",
            "l1ChainId": input.l1_chain_id,
            "opening": {
                "roomState": 1,
                "deploymentDomain": input.journal.deployment_domain,
                "eip712DomainSeparator": B256::repeat_byte(0x77),
                "roomId": input.journal.room_id,
                "authorizationMode": input.journal.authorization_mode,
                "coldTemplateId": input.journal.cold_template_id,
                "proofProgramId": input.journal.proof_program_id,
                "proofSystemVersion": input.journal.proof_system_version,
                "policyHash": input.journal.policy_hash,
                "stateRoot": input.journal.pre_state_root,
                "participantRoot": input.journal.pre_participant_root,
                "participantEpoch": input.journal.pre_participant_epoch,
                "participantCount": input.journal.pre_participant_count,
                "participantCapacity": input.journal.participant_capacity,
                "approverRoot": input.journal.pre_roster_root,
                "approverEpoch": input.journal.pre_roster_epoch,
                "activeCount": input.journal.pre_active_count,
                "batchIndex": input.journal.batch_index - 1,
                "l2BlockHeight": input.journal.start_l2_block - 1,
                "approverChangeCursor": input.journal.roster_change_cursor_before,
                "inboxCursor": input.journal.inbox_cursor_before,
                "admissionCursor": input.journal.admission_cursor_before,
                "forcedCursor": input.journal.forced_cursor_before,
                "importCursor": input.journal.import_cursor_before,
                "outboxEpoch": input.journal.outbox_epoch - 1,
                "maximumAdmissionWindow": 128,
                "bondEpoch": 1,
                "admissionSigner": Address::repeat_byte(0x44),
                "minimumServiceBond": U256::ZERO,
                "serviceBond": U256::ZERO,
                "liabilitiesHash": input.journal.pre_liabilities_hash,
                "observedL1Block": 1
            },
            "closing": {
                "participantRoot": input.journal.post_participant_root,
                "participantEpoch": input.journal.post_participant_epoch,
                "participantCount": input.journal.post_participant_count,
                "l1InclusionDeadline": input.journal.l1_inclusion_deadline,
                "close": input.journal.close
            },
            "policy": input.policy,
            "approverCapacity": input.roster_capacity,
            "preApprovers": input.pre_roster,
            "postApprovers": input.post_roster,
            "approverChanges": input.roster_changes,
            "admissions": input.admissions,
            "forcedTransactions": input.forced_transactions,
            "preLiabilities": input.pre_liabilities,
            "postLiabilities": input.post_liabilities,
            "deposits": input.deposits,
            "withdrawals": input.withdrawals,
            "withdrawalCapacity": input.withdrawal_capacity,
            "l1Import": input.l1_import,
            "compactState": input.compact_state,
            "blocks": input.blocks,
        })
    }

    fn admission_signer() -> (SigningKey, Address) {
        let key = SigningKey::from_bytes(&B256::with_last_byte(9).0.into())
            .expect("fixed admission test key");
        let point = key.verifying_key().to_encoded_point(false);
        let address = Address::from_slice(&keccak256(&point.as_bytes()[1..]).as_slice()[12..]);
        (key, address)
    }

    fn request_with_signed_admission() -> serde_json::Value {
        let mut value = fixture_live_request();
        let raw: Bytes = serde_json::from_value(value["blocks"][0]["raw_txs"][0].clone())
            .expect("fixture first transaction decodes");
        let transaction_hash = keccak256(raw);
        let mut record = AdmissionRecordV5 {
            receipt: AdmissionReceiptV5 {
                admission_id: 1,
                transaction_hash,
                deposit_inbox_id: 0,
                deposit_content_hash: B256::ZERO,
                deadline_block: 100,
                maximum_batch_index: 1,
                bond_epoch: 1,
                admission_fee: U256::ZERO,
                signature: Bytes::new(),
            },
            outcome: AdmissionOutcomeV5 {
                admission_id: 1,
                transaction_hash,
                status: 0,
                l2_block_number: value["blocks"][0]["block_number"].as_u64().unwrap(),
                transaction_index: 0,
                reason_hash: B256::ZERO,
            },
        };
        let (key, signer) = admission_signer();
        let domain: B256 = serde_json::from_value(
            value["opening"]["eip712DomainSeparator"].clone(),
        )
        .unwrap();
        let struct_hash = admission_receipt_struct_hash(91, &record);
        let mut typed = Vec::with_capacity(66);
        typed.extend_from_slice(b"\x19\x01");
        typed.extend_from_slice(domain.as_slice());
        typed.extend_from_slice(struct_hash.as_slice());
        let (signature, recovery) = key
            .sign_prehash_recoverable(keccak256(typed).as_slice())
            .expect("sign admission test receipt");
        let mut signature_bytes = signature.to_bytes().to_vec();
        signature_bytes.push(recovery.to_byte());
        record.receipt.signature = Bytes::from(signature_bytes);
        value["opening"]["admissionSigner"] = serde_json::json!(signer);
        value["admissions"] = serde_json::to_value([record]).unwrap();
        value
    }

    #[test]
    fn prepares_fixture_equivalent_live_witness_and_submission() {
        let value = fixture_live_request();
        let output = cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .expect("live prepare succeeds");
        assert_eq!(output["fixture"], false);
        assert_eq!(output["preparedFrom"], "live-room-engine-state");
        assert_eq!(output["journal"]["protocol_version"], 6);
        assert_eq!(output["provisionalSubmission"]["journal"]["protocolVersion"], 6);
        assert_eq!(output["provisionalSubmission"]["approvals"], serde_json::json!([]));
        assert_eq!(output["proofRequest"]["production"], true);
        assert!(output["roomWitnessB64"].as_str().unwrap().len() > 100);
        assert_eq!(output["prepareArtifactDigest"], output["contentAddress"]);
    }

    #[test]
    fn rejects_policy_or_opening_state_drift() {
        let mut value = fixture_live_request();
        value["opening"]["policyHash"] = serde_json::json!(B256::repeat_byte(0x99));
        let error = cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .expect_err("policy drift is rejected");
        assert!(error.to_string().contains("policyHash"));

        let mut value = fixture_live_request();
        value["opening"]["stateRoot"] = serde_json::json!(B256::repeat_byte(0x55));
        let error = cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .expect_err("state drift is rejected");
        assert!(error.to_string().contains("native live room preparation"));
    }

    #[test]
    fn rejects_fixture_mode_closed_room_and_legacy_authorization() {
        let mut value = fixture_live_request();
        value["production"] = serde_json::json!(false);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap()).is_err());

        let mut value = fixture_live_request();
        value["opening"]["roomState"] = serde_json::json!(2);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap()).is_err());

        let mut value = fixture_live_request();
        value["opening"]["authorizationMode"] = serde_json::json!(0);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap()).is_err());
    }

    #[test]
    fn proof_request_and_solidity_projection_share_one_exact_journal_identity() {
        let value = fixture_live_request();
        let output = cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap()).unwrap();
        let proof_request = serde_json::to_string(&output["proofRequest"]).unwrap();
        let (decoded, request, _bytes, address) =
            room_witness_from_stdin(&proof_request).expect("proofRequest re-decodes");
        let journal: BatchJournalV5 = serde_json::from_value(output["journal"].clone()).unwrap();
        assert_eq!(decoded.journal, journal);
        assert_eq!(request["production"], true);
        assert_eq!(request["proofMode"], "groth16");
        assert_eq!(
            output["prepareArtifactDigest"],
            address.input_digest.trim_start_matches("0x")
        );
        assert_eq!(output["proverJobIdentity"], address.job_id);
        assert_eq!(
            output["journalHash"],
            format!("0x{}", hex::encode(hash_batch_journal_v5(&journal)))
        );
        assert_eq!(output["provisionalSubmission"]["journal"], solidity_journal(&journal));
        assert_eq!(output["provisionalSubmission"]["seal"], "0x");
        assert_eq!(output["provisionalSubmission"]["approvals"], serde_json::json!([]));
        assert_eq!(output["provisionalSubmission"]["approverChanges"], serde_json::json!([]));
    }

    #[test]
    fn accepts_one_canonical_signed_admission_and_rejects_every_signature_boundary_mutation() {
        let value = request_with_signed_admission();
        let output = cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .expect("canonical admission prepares");
        assert_eq!(output["provisionalSubmission"]["admissions"].as_array().unwrap().len(), 1);

        let mut changed = value.clone();
        changed["opening"]["eip712DomainSeparator"] = serde_json::json!(B256::repeat_byte(0xaa));
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&changed).unwrap())
            .unwrap_err().to_string().contains("not signed"));

        let mut changed = value.clone();
        changed["admissions"][0]["receipt"]["maximum_batch_index"] = serde_json::json!(0);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&changed).unwrap())
            .unwrap_err().to_string().contains("outside"));

        let mut changed = value.clone();
        changed["admissions"][0]["receipt"]["signature"] = serde_json::json!("0x00");
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&changed).unwrap())
            .unwrap_err().to_string().contains("exactly 65 bytes"));

        let mut changed = value;
        changed["admissions"][0]["outcome"]["transaction_index"] = serde_json::json!(1);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&changed).unwrap())
            .unwrap_err().to_string().contains("native live room preparation"));
    }

    #[test]
    fn prepares_a_terminal_batch_for_a_recovery_closed_room() {
        let mut value = fixture_live_request();
        value["terminal"] = serde_json::json!(true);
        value["opening"]["roomState"] = serde_json::json!(2);
        value["closing"]["close"] = serde_json::json!(true);
        let output = cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .expect("terminal preparation succeeds against the last accepted state");
        assert_eq!(output["journal"]["close"], true);
        assert_eq!(output["provisionalSubmission"]["journal"]["close"], true);
    }

    #[test]
    fn rejects_terminal_flag_on_open_rooms_and_non_close_journals() {
        // Terminal preparation is only for recovery-closed rooms.
        let mut value = fixture_live_request();
        value["terminal"] = serde_json::json!(true);
        value["closing"]["close"] = serde_json::json!(true);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .unwrap_err()
            .to_string()
            .contains("wrong room state"));

        // And it must actually close the room.
        let mut value = fixture_live_request();
        value["terminal"] = serde_json::json!(true);
        value["opening"]["roomState"] = serde_json::json!(2);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .unwrap_err()
            .to_string()
            .contains("requires a closing journal"));
    }

    #[test]
    fn rejects_nonzero_withdrawal_capacity_without_withdrawals() {
        let mut value = fixture_live_request();
        value["withdrawalCapacity"] = serde_json::json!(4);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .unwrap_err()
            .to_string()
            .contains("carries no withdrawals"));
    }

    #[test]
    fn decimal_string_amounts_decode_identically_to_hex_and_wide_numbers_are_rejected() {
        // `ruint`'s FromStr treats an unprefixed string as decimal; the web2
        // host emits decimal strings for U256 fields, so lock that in.
        let mut value = fixture_live_request();
        value["deposits"] = serde_json::json!([{
            "inbox_id": 1,
            "depositor": Address::repeat_byte(0xa1),
            "beneficiary": Address::repeat_byte(0xb1),
            "asset": Address::ZERO,
            "amount": "0x64",
            "queued_at_block": 100,
            "consumed": false,
            "refunded": false
        }]);
        value["withdrawals"] = serde_json::json!([{
            "index": 0,
            "approver_epoch": 1,
            "recipient": Address::repeat_byte(0xbe),
            "asset": Address::ZERO,
            "amount": "0xff"
        }]);
        value["postLiabilities"] = serde_json::json!([{
            "asset": Address::ZERO,
            "pending": "0x0",
            "controlled": "0x2710",
            "claimable": "0x0",
            "paid": "0x0"
        }]);
        let hex: LiveBatchPrepareRequestV1 =
            serde_json::from_value(value.clone()).expect("hex-amount request decodes");

        let mut decimal = value.clone();
        decimal["deposits"][0]["amount"] = serde_json::json!("100");
        // The deposit's u64 id fields carry the same decimal-string form a direct
        // JSON producer (the TypeScript node emitting bigints) uses.
        decimal["deposits"][0]["inbox_id"] = serde_json::json!("1");
        decimal["deposits"][0]["queued_at_block"] = serde_json::json!("100");
        decimal["withdrawals"][0]["amount"] = serde_json::json!("255");
        decimal["postLiabilities"][0]["pending"] = serde_json::json!("0");
        decimal["postLiabilities"][0]["controlled"] = serde_json::json!("10000");
        decimal["postLiabilities"][0]["claimable"] = serde_json::json!("0");
        decimal["postLiabilities"][0]["paid"] = serde_json::json!("0");
        let parsed: LiveBatchPrepareRequestV1 =
            serde_json::from_value(decimal).expect("decimal-string amounts decode");
        assert_eq!(parsed.deposits, hex.deposits);
        assert_eq!(parsed.withdrawals, hex.withdrawals);
        assert_eq!(parsed.post_liabilities, hex.post_liabilities);
        assert_eq!(parsed.deposits[0].amount, U256::from(100u64));
        assert_eq!(parsed.deposits[0].inbox_id, 1);
        assert_eq!(parsed.deposits[0].queued_at_block, 100);
        assert_eq!(parsed.post_liabilities[0].controlled, U256::from(10_000u64));

        // The remaining two u64 id fields (forced_id, deposit_inbox_id) decode
        // the same way, and the widened deserializer still round-trips through
        // the guest's non-self-describing bincode witness format.
        let forced: ForcedTransactionV5 = serde_json::from_value(serde_json::json!({
            "forced_id": "7",
            "raw_transaction": "0x02",
            "outcome": {
                "admission_id": 7,
                "transaction_hash": B256::ZERO,
                "status": 0,
                "l2_block_number": 0,
                "transaction_index": 0,
                "reason_hash": B256::ZERO
            }
        }))
        .expect("decimal-string forced_id decodes");
        assert_eq!(forced.forced_id, 7);
        let round_tripped: ForcedTransactionV5 =
            bincode::deserialize(&bincode::serialize(&forced).unwrap()).unwrap();
        assert_eq!(round_tripped, forced);

        let receipt: AdmissionReceiptV5 = serde_json::from_value(serde_json::json!({
            "admission_id": 1,
            "transaction_hash": B256::ZERO,
            "deposit_inbox_id": "9",
            "deposit_content_hash": B256::ZERO,
            "deadline_block": 100,
            "maximum_batch_index": 1,
            "bond_epoch": 1,
            "admission_fee": "0x0",
            "signature": "0x"
        }))
        .expect("decimal-string deposit_inbox_id decodes");
        assert_eq!(receipt.deposit_inbox_id, 9);

        // A bare JSON number wider than u64 cannot round-trip losslessly and
        // must be refused rather than silently truncated.
        let mut wide = value;
        wide["postLiabilities"][0]["controlled"] =
            serde_json::from_str("18446744073709551616").expect("2^64 parses as a JSON number");
        assert!(
            serde_json::from_value::<LiveBatchPrepareRequestV1>(wide).is_err(),
            "JSON numbers above u64::MAX must be rejected"
        );
    }

    #[test]
    fn rejects_closing_fact_regression_approvers_and_liability_drift_before_proving() {
        let mut value = fixture_live_request();
        value["closing"]["l1InclusionDeadline"] = value["opening"]["observedL1Block"].clone();
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap()).is_err());

        let mut value = fixture_live_request();
        value["closing"]["participantCount"] = serde_json::json!(129);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap()).is_err());

        let mut value = fixture_live_request();
        value["preApprovers"] = serde_json::json!([{
            "index": 0, "member": Address::repeat_byte(0x91), "joined_epoch": 1
        }]);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .unwrap_err().to_string().contains("cannot carry checkpoint approvers"));

        let mut value = fixture_live_request();
        value["opening"]["liabilitiesHash"] = serde_json::json!(B256::repeat_byte(0x92));
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .unwrap_err().to_string().contains("liabilities"));

        let mut value = fixture_live_request();
        value["blocks"][0]["block_number"] = serde_json::json!(99);
        assert!(cmd_prepare_live_room_batch(&serde_json::to_string(&value).unwrap())
            .unwrap_err().to_string().contains("continue"));
    }
}
