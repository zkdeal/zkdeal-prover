//! Exact Alloy `native-keccak` bridge for the RISC Zero Keccak accelerator.
//!
//! Alloy calls the C ABI below for every one-shot Ethereum Keccak-256 hash.
//! RISC Zero proves each permutation with its dedicated Keccak circuit and
//! folds those assumptions into the ordinary zkVM receipt during guest
//! finalization. The sponge, Ethereum domain separator and output byte order
//! stay inside this guest, so the host never supplies a trusted hash result.

#[cfg(target_os = "zkvm")]
const KECCAK256_RATE: usize = 136;

#[cfg(target_os = "zkvm")]
#[inline]
fn permute(state: &mut [u64; 25]) {
    risc0_zkvm::guest::env::risc0_keccak_update(state);
}

#[cfg(target_os = "zkvm")]
#[inline]
fn absorb_block(state: &mut [u64; 25], block: &[u8; KECCAK256_RATE]) {
    for (lane, bytes) in block.chunks_exact(8).enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(bytes);
        state[lane] ^= u64::from_le_bytes(word);
    }
    permute(state);
}

/// Compute legacy Ethereum Keccak-256 through RISC Zero's exact accelerator.
///
/// # Safety
///
/// This function implements Alloy's `native-keccak` ABI. `input` must name
/// `len` readable bytes and `output` must name 32 writable bytes. Alloy calls
/// it with pointers obtained from a Rust slice and `MaybeUninit<B256>`.
#[cfg(target_os = "zkvm")]
#[no_mangle]
pub unsafe extern "C" fn native_keccak256(input: *const u8, len: usize, output: *mut u8) {
    let input = unsafe { core::slice::from_raw_parts(input, len) };
    let output = unsafe { core::slice::from_raw_parts_mut(output, 32) };
    let mut state = [0u64; 25];

    let mut full_blocks = input.chunks_exact(KECCAK256_RATE);
    for chunk in &mut full_blocks {
        let block: &[u8; KECCAK256_RATE] = chunk
            .try_into()
            .expect("chunks_exact always returns one complete Keccak rate block");
        absorb_block(&mut state, block);
    }

    // Ethereum Keccak uses the legacy 0x01 domain byte, not SHA3's 0x06.
    // The final 0x80 bit implements pad10*1. A message whose length is an
    // exact multiple of the rate receives a fresh padding-only block.
    let remainder = full_blocks.remainder();
    let mut final_block = [0u8; KECCAK256_RATE];
    final_block[..remainder.len()].copy_from_slice(remainder);
    final_block[remainder.len()] ^= 0x01;
    final_block[KECCAK256_RATE - 1] ^= 0x80;
    absorb_block(&mut state, &final_block);

    for (chunk, lane) in output.chunks_exact_mut(8).zip(state.iter()) {
        chunk.copy_from_slice(&lane.to_le_bytes());
    }
}
