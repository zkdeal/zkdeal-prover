//! The two REVM inspectors: the certified-policy observer that every room
//! transaction runs under, and the Osaka EIP-7610 compatibility correction.

use alloy_primitives::{Address, Bytes, TxKind, U256};
use revm::interpreter::interpreter_types::{Jumps, MemoryTr};
use revm::{
    context_interface::{journaled_state::account::JournaledAccountTr, ContextTr, JournalTr},
    inspector::Inspector,
    interpreter::{
        CallInputs, CallScheme, CreateInputs, CreateOutcome, Gas, InstructionResult, Interpreter,
        InterpreterResult,
    },
};

use super::{AllowedCallKind, ExecutionPolicyV4};
use crate::StateMap;

#[derive(Clone, Debug)]
pub(crate) struct CertifiedPolicyInspectorV4<'a> {
    policy: &'a ExecutionPolicyV4,
    pub(crate) violation: Option<String>,
    proof_work: InspectorProofWork,
    opcode_gadgets: bool,
    #[cfg(not(target_arch = "riscv32"))]
    possible_fused_step: Option<usize>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InspectorProofWork {
    pub opcode_steps: u64,
    pub fused_motif_hits: u64,
    pub fused_motif_opcodes: u64,
    pub keccak_opcodes: u64,
    pub call_opcodes: u64,
    pub precompile_calls: u64,
    pub max_memory_bytes: u64,
}

impl<'a> CertifiedPolicyInspectorV4<'a> {
    pub(crate) fn new(policy: &'a ExecutionPolicyV4, opcode_gadgets: bool) -> Self {
        Self {
            policy,
            violation: None,
            proof_work: InspectorProofWork::default(),
            opcode_gadgets,
            #[cfg(not(target_arch = "riscv32"))]
            possible_fused_step: None,
        }
    }

    pub(crate) fn reset(&mut self) {
        self.violation = None;
    }

    pub(crate) fn proof_work(&self) -> InspectorProofWork {
        self.proof_work
    }

    /// Validate the transaction's outermost frame explicitly. Inspector
    /// callbacks are still used for every nested EVM call, but revm is not a
    /// protocol boundary for whether the root transaction invokes `call()`.
    /// Keeping this check outside that implementation detail makes it
    /// impossible for a member transaction to bypass the certified target and
    /// selector allow-list.
    pub(crate) fn validate_transaction_entry(
        &self,
        caller: Address,
        kind: &TxKind,
        input: &[u8],
    ) -> Result<(), String> {
        if !self.policy.certified {
            return Ok(());
        }
        let target = match kind {
            TxKind::Create => {
                return if self.policy.allow_contract_creation {
                    Ok(())
                } else {
                    Err("contract creation is disabled by the preset".into())
                };
            }
            TxKind::Call(target) => *target,
        };
        let selector = input.get(..4).map(|bytes| {
            let mut out = [0u8; 4];
            out.copy_from_slice(bytes);
            out
        });
        if !self
            .policy
            .allows_call(caller, target, AllowedCallKind::Call, selector)
        {
            return Err(format!(
                "root transaction {caller} -> {target} (Call, selector {selector:?}) is outside the certified envelope"
            ));
        }
        self.policy
            .validate_active_member_arguments(target, selector, input)
    }
}

/// REVM 36 implements Osaka except for EIP-7610's storage-only CREATE
/// collision rule. Keep the compatibility correction in one inspector that
/// is shared by ordinary room execution and the official EEST runner.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsakaSemanticInspector;

fn storage_collision_outcome<CTX>(
    context: &mut CTX,
    inputs: &mut CreateInputs,
) -> Option<CreateOutcome>
where
    CTX: ContextTr<Db = StateMap>,
{
    // Returning an inspector override happens before revm's create frame, so
    // reproduce the observable prefix of that frame: depth/funds/nonce checks,
    // the caller nonce bump, and warming the destination.
    if context.journal().depth() > 1024 {
        return None;
    }
    let (caller_balance, caller_nonce) = {
        let caller = context.journal_mut().load_account(inputs.caller()).ok()?;
        (caller.data.info.balance, caller.data.info.nonce)
    };
    if caller_balance < inputs.value() || caller_nonce == u64::MAX {
        return None;
    }
    let created = inputs.created_address(caller_nonce);
    let storage_only_collision = context.db().accounts.get(&created).is_some_and(|account| {
        !account.storage.is_empty() && account.nonce == 0 && account.code.is_empty()
    });
    if !storage_only_collision {
        return None;
    }

    {
        let mut caller = context
            .journal_mut()
            .load_account_mut(inputs.caller())
            .ok()?;
        if !caller.data.bump_nonce() {
            return None;
        }
    }
    context.journal_mut().load_account(created).ok()?;
    Some(CreateOutcome::new(
        InterpreterResult {
            result: InstructionResult::CreateCollision,
            gas: Gas::new(inputs.gas_limit()),
            output: Bytes::new(),
        },
        None,
    ))
}

impl<CTX> Inspector<CTX> for OsakaSemanticInspector
where
    CTX: ContextTr<Db = StateMap>,
{
    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        storage_collision_outcome(context, inputs)
    }
}

impl<CTX> Inspector<CTX> for CertifiedPolicyInspectorV4<'_>
where
    CTX: ContextTr<Db = StateMap>,
{
    fn step(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        let opcode = interp.bytecode.opcode();
        self.proof_work.opcode_steps = self.proof_work.opcode_steps.saturating_add(1);
        // Motif counters are host/debug telemetry, not a public proof claim.
        // The RISC-V guest omits this self-observation so the optimization is
        // measured by the host without adding cycles to the proved trace.
        #[cfg(not(target_arch = "riscv32"))]
        {
            if self.opcode_gadgets
                && matches!(
                    opcode,
                    0x01 | 0x02
                        | 0x03
                        | 0x04
                        | 0x10
                        | 0x11
                        | 0x12
                        | 0x14
                        | 0x15
                        | 0x16
                        | 0x17
                        | 0x19
                        | 0x1b
                        | 0x1c
                )
            {
                self.possible_fused_step = Some(interp.bytecode.pc());
            } else {
                self.possible_fused_step = None;
            }
        }
        if opcode == 0x20 {
            self.proof_work.keccak_opcodes = self.proof_work.keccak_opcodes.saturating_add(1);
        }
        if matches!(opcode, 0xf0 | 0xf1 | 0xf2 | 0xf4 | 0xf5 | 0xfa) {
            self.proof_work.call_opcodes = self.proof_work.call_opcodes.saturating_add(1);
        }
        self.proof_work.max_memory_bytes = self
            .proof_work
            .max_memory_bytes
            .max(interp.memory.size() as u64);
        if interp.memory.size() > self.policy.max_memory_bytes {
            self.violation.get_or_insert_with(|| {
                format!(
                    "EVM memory {} bytes exceeds preset maxMemoryPages ({} bytes)",
                    interp.memory.size(),
                    self.policy.max_memory_bytes
                )
            });
        }
    }

    fn step_end(&mut self, interp: &mut Interpreter, _context: &mut CTX) {
        #[cfg(not(target_arch = "riscv32"))]
        {
            if let Some(start_pc) = self.possible_fused_step.take() {
                if interp.bytecode.pc() == start_pc.saturating_add(2) {
                    self.proof_work.opcode_steps = self.proof_work.opcode_steps.saturating_add(1);
                    self.proof_work.fused_motif_hits =
                        self.proof_work.fused_motif_hits.saturating_add(1);
                    self.proof_work.fused_motif_opcodes =
                        self.proof_work.fused_motif_opcodes.saturating_add(2);
                }
            }
        }
        if interp.memory.size() > self.policy.max_memory_bytes {
            self.violation.get_or_insert_with(|| {
                format!(
                    "EVM memory {} bytes exceeds preset maxMemoryPages ({} bytes)",
                    interp.memory.size(),
                    self.policy.max_memory_bytes
                )
            });
        }
    }

    fn call(
        &mut self,
        context: &mut CTX,
        inputs: &mut CallInputs,
    ) -> Option<revm::interpreter::CallOutcome> {
        if self.violation.is_some() {
            return None;
        }
        let kind = match inputs.scheme {
            CallScheme::Call => AllowedCallKind::Call,
            CallScheme::StaticCall => AllowedCallKind::StaticCall,
            CallScheme::DelegateCall => AllowedCallKind::DelegateCall,
            CallScheme::CallCode => {
                self.violation = Some("CALLCODE is outside every certified preset".into());
                return None;
            }
        };
        if ExecutionPolicyV4::is_precompile(inputs.bytecode_address) {
            self.proof_work.precompile_calls = self.proof_work.precompile_calls.saturating_add(1);
        }
        let input = inputs.input.bytes(context);
        let selector = input.get(..4).map(|bytes| {
            let mut out = [0u8; 4];
            out.copy_from_slice(bytes);
            out
        });
        if !self
            .policy
            .allows_call(inputs.caller, inputs.bytecode_address, kind, selector)
        {
            self.violation = Some(format!(
                "call {} -> {} ({kind:?}, selector {selector:?}) is outside the certified envelope",
                inputs.caller, inputs.bytecode_address
            ));
        } else if let Err(error) =
            self.policy
                .validate_active_member_arguments(inputs.bytecode_address, selector, &input)
        {
            self.violation = Some(error);
        }
        None
    }

    fn create(&mut self, context: &mut CTX, inputs: &mut CreateInputs) -> Option<CreateOutcome> {
        if !self.policy.allow_contract_creation {
            self.violation
                .get_or_insert_with(|| "contract creation is disabled by the preset".into());
        }

        storage_collision_outcome(context, inputs)
    }

    fn selfdestruct(&mut self, contract: Address, target: Address, _value: U256) {
        if !self.policy.allow_self_destruct {
            self.violation.get_or_insert_with(|| {
                format!("selfdestruct {contract} -> {target} is disabled by the preset")
            });
        }
    }
}
