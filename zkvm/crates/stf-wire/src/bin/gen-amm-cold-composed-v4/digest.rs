//! Self-contained hashing and encoding used to derive the prover job content
//! addresses and the Bento input frame — no dependency beyond the standard
//! library, so the emitted request files can be re-derived by hand.

use crate::{invalid, DynResult, PROOF_MODE};

pub(crate) fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or_default();
        let c = chunk.get(2).copied().unwrap_or_default();
        output.push(TABLE[(a >> 2) as usize] as char);
        output.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(c & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut padded = bytes.to_vec();
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for block in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            w[index] = u32::from_be_bytes(word.try_into().expect("four-byte SHA word"));
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (target, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *target = target.wrapping_add(value);
        }
    }
    let mut output = [0u8; 32];
    for (index, value) in h.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    output
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn content_address(
    domain: &[u8],
    witness: &[u8],
    program_id: &[u8; 32],
    preset_hash: &[u8; 32],
) -> (String, String) {
    let digest = sha256(witness);
    let mut job = Vec::with_capacity(domain.len() + 32 * 3 + 15);
    job.extend_from_slice(domain);
    job.extend_from_slice(&digest);
    job.extend_from_slice(program_id);
    job.extend_from_slice(preset_hash);
    job.extend_from_slice(b"risc0");
    job.extend_from_slice(PROOF_MODE.as_bytes());
    (hex(&digest), hex(&sha256(&job)))
}

/// Exact RISC Zero `ExecutorEnv::write_frame` encoding consumed by the guest's
/// `env::read_frame`: one little-endian u32 byte length followed by the raw
/// payload bytes.
pub(crate) fn risc0_frame_input(bytes: &[u8]) -> DynResult<Vec<u8>> {
    let len = u32::try_from(bytes.len()).map_err(|_| invalid("Bento input exceeds u32"))?;
    let capacity = bytes
        .len()
        .checked_add(std::mem::size_of::<u32>())
        .ok_or_else(|| invalid("Bento input size overflow"))?;
    let mut encoded = Vec::with_capacity(capacity);
    encoded.extend_from_slice(&len.to_le_bytes());
    encoded.extend_from_slice(bytes);
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::risc0_frame_input;

    #[test]
    fn risc0_frame_uses_byte_length_and_raw_payload() {
        let payload = b"ZK4B";
        let encoded = risc0_frame_input(payload).expect("frame encoding");

        assert_eq!(encoded, [4, 0, 0, 0, b'Z', b'K', b'4', b'B']);
    }
}
