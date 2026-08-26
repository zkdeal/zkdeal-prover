/**
 * Real inputs for the precompiles that reject a zeroed buffer.
 *
 * Most precompiles accept zero bytes and charge their schedule, so the sweep can
 * measure them without any vector at all. Four cannot, and two separate causes
 * were conflated when they were first reported as unmeasured:
 *
 *   1. A HARNESS BUG. The STATICCALL frame used argsOffset = retOffset = 0, so
 *      each call's return data overwrote its own input. The first call in a unit
 *      chain succeeded and every later one parsed the previous output as input.
 *      BLAKE2F accepts 213 zero bytes perfectly well - it returns the BLAKE2b IV
 *      with zero rounds - and the next call then read rounds = 147,439,347,
 *      exceeded its gas and burned everything. BLS12 pairing failed the same
 *      way. That is fixed by giving the return window its own region, not by
 *      supplying a vector.
 *
 *   2. GENUINELY DEGENERATE INPUTS. Even with the aliasing fixed, a zeroed
 *      buffer decodes to the point at infinity, which the curve precompiles
 *      short-circuit: bn254 pairing skips any pair containing infinity and
 *      returns success having done no pairing at all. Measuring that prices the
 *      early-exit, not the operation. KZG rejects zeros outright at the
 *      versioned-hash check.
 *
 * Every vector below is sourced from something already in this repository, and
 * each is a valid encoding that makes the precompile do its full work.
 */

/** BLAKE2F, EIP-152 test vector 4: BLAKE2b-512 of "abc", final block, t0 = 3. */
const BLAKE2F_BODY =
  '48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5'
  + 'd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b'
  + '6162630000000000000000000000000000000000000000000000000000000000'
  + '0000000000000000000000000000000000000000000000000000000000000000'
  + '0000000000000000000000000000000000000000000000000000000000000000'
  + '0000000000000000000000000000000000000000000000000000000000000000'
  + '0300000000000000'
  + '0000000000000000'
  + '01'

/**
 * BLAKE2F with an explicit round count.
 *
 * Gas is exactly the round count, and rounds live in the first four bytes, so
 * sweeping only those gives a clean per-round gradient against a constant
 * 213-byte input - size and work are separated by construction.
 */
export function blake2f(rounds: number): string {
  return rounds.toString(16).padStart(8, '0') + BLAKE2F_BODY
}

/**
 * BN254 pairing, assembled from the card-deck Groth16 proof and its verifying
 * key exactly as `CardDeckInitGroth16VerifierV5.checkPairing` orders the terms:
 * (-A, B), (alpha1, beta2), (vk_x, gamma2), (C, delta2). Four pairs, returns 1.
 *
 * Slicing the front of it gives valid smaller checks: k=1 and k=2 return 0 but
 * still run the full Miller loop and final exponentiation, which is the work
 * being priced.
 */
const BN254_PAIRING_K4 =
  '02d2f50e8c40b67ce0fa4790de06172a6952347a980429b8249729e43964bff1'
  + '2eda0fb1c8b37c6a8f943a403df49a6a7aaab7b0de30ebb0e7f74c35b9b74f66'
  + '11b64b85e45c10dd9d9f779aaffba48712952039cd6a1aaf3f99dd879ea0f000'
  + '2000e02824debbd4a9465c44e8f0e142b47b85fbf73c98764f4b4ae0748511be'
  + '0c92ca91a22bdd134575a56a2164f1a897ea947b5fba889e1ce0d9d7663a0848'
  + '2092bb670037585a578bda671adead5b37c4b5ba12a6f83146e134eabe40d780'
  + '2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e2'
  + '14bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d1926'
  + '0967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c'
  + '0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab'
  + '304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a7'
  + '1739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8'
  + '00e51520941c90014845632caac619e230837a64f16918ee637fa53ca96120f7'
  + '223e9354dbf5096580319990c81b3e31701f5526eedd8218961f355de1c96273'
  + '198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2'
  + '1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed'
  + '090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b'
  + '12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa'
  + '268c90fb037218dde0fd01199c8552ea0c3bff4c83f53bc1f5f9245681036a57'
  + '1eb44492982871d544285bb668a9e40d66fca8f515f47c88516522dcca662ba8'
  + '198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2'
  + '1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed'
  + '090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b'
  + '12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa'

export function bn254Pairing(pairs: number): string {
  return BN254_PAIRING_K4.slice(0, pairs * 192 * 2)
}

/**
 * BLS12-381 pairing, from the tracked BLS settlement bench fixture, ordered as
 * `BLSSettlement.sol` builds it: negAggPubKeyG1, messageG2, G1 generator,
 * aggSigG2. Two pairs, returns 1. Every coordinate carries the 16-byte zero
 * padding EIP-2537 requires.
 */
const BLS12_PAIRING_K2 =
  '00000000000000000000000000000000127acf126d2da9d9f2c4e398a971aa2b8bb4deac523902d468ba454b419c0308e16abb8bfdc21da6b8ba0a6a9118da6b'
  + '000000000000000000000000000000000b9e21950f4aa31af01fb7cf1468f9481f9cf28ef23991bcedbac28e4b6cb3c67f56bfa5d1b9dadca27d4c7febddde14'
  + '00000000000000000000000000000000090a9693f37c26786edb3259c6aad1285915b7e0726b0c2f7432f998752ae3b6f11107ac737c9a6a3bf3b94849a7046a'
  + '0000000000000000000000000000000002980452edf2b1100c3a9e0456706a2210f34500222cc4b8adb20c09a61f37cf689a70af71c7c64d15e7f6b8531af9f5'
  + '000000000000000000000000000000000991e05bcf3b480b4ef7059a680c07283bc7adfc9a6a3bbde7c8e32ee4e230e06e7b23119096b07a6f24731323e21762'
  + '0000000000000000000000000000000009674eb155261aab57f9e2bf59c5fda21f1952fb2543b44614ceb5005b06e84b316a9118cde14afa2e4a57d034f5ac28'
  + '0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb'
  + '0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1'
  + '000000000000000000000000000000000f017f4d5ef565f80e2e6db2af078378065948bdc7e0ecbf1810c859be5ae3a70c596e50f95363e4ff0c8789c18ddb8a'
  + '000000000000000000000000000000000837853531ea532b1cd43169421ae2ab6b2f4bb76c8315cddbc663623731487ac87e1092117c188c3640642c51d99cce'
  + '0000000000000000000000000000000002b48842436b561afaddd8638bcf1fb8dd085620f98df5ec42f8918aa7c9c7899fc6a01335d6337b987735498a43314a'
  + '000000000000000000000000000000000a6276422011ef8155bcd56d130223d746781f19879e6eaeb00bb559d595971430463d381457f7cd0f114a1ab44a7df1'

export function bls12Pairing(pairs: number): string {
  return BLS12_PAIRING_K2.slice(0, pairs * 384 * 2)
}

/**
 * KZG point evaluation. c-kzg's `verify_kzg_proof_case_correct_proof_4_4`.
 *
 * Deliberately NOT the infinity-commitment variant that also passes: a
 * compressed-infinity commitment short-circuits the scalar multiplications and
 * would price an early exit rather than the verification.
 *
 * This is measurable in the guest despite earlier doubt. revm is pinned with
 * default features off, so `c-kzg` and `blst` are not compiled in and the
 * arkworks backend reads the ceremony point from a compile-time constant. No
 * trusted-setup file is loaded at runtime.
 */
export const KZG_POINT_EVALUATION =
  '01e798154708fe7789429634053cbf9f99b619f9f084048927333fce637f549b'
  + '73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000'
  + '1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9'
  + '8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca2'
  + '5f26936857bc3a7c2539ea8ec3a952b7a62ad71d14c5719385c0686f18714304'
  + '75bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c'

/**
 * The individual curve points inside the pairing vectors, reused for the
 * point-arithmetic precompiles.
 *
 * A pairing input is a flat array of (G1, G2) pairs, so every point in it is
 * already a validated, non-degenerate, subgroup-checked encoding. Slicing them
 * back out is strictly better than inventing new points: there is nothing left
 * to get wrong, and the provenance of every byte stays visible in one place.
 *
 * bn254 lays out 64-byte G1 then 128-byte G2 per pair; BLS12-381 lays out
 * 128-byte G1 then 256-byte G2, every coordinate 16-byte zero padded.
 */
function bn254G1(pair: 0 | 1 | 2 | 3): string {
  return BN254_PAIRING_K4.slice(pair * 192 * 2, pair * 192 * 2 + 64 * 2)
}

function bls12G1(pair: 0 | 1): string {
  return BLS12_PAIRING_K2.slice(pair * 384 * 2, pair * 384 * 2 + 128 * 2)
}

function bls12G2(pair: 0 | 1): string {
  return BLS12_PAIRING_K2.slice(pair * 384 * 2 + 128 * 2, (pair + 1) * 384 * 2)
}

/**
 * Scalars one below each curve's group order.
 *
 * Scalar multiplication is windowed over the scalar's bit length, so a small
 * scalar exits early and prices a fraction of the operation. A near-maximal
 * scalar prices the case a verifier actually has to budget for. Both are
 * in range: `r - 1 < r`.
 */
const BN254_SCALAR_MAX = '30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000'.padStart(64, '0')
const BLS12_SCALAR_MAX = '73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000'

/**
 * ECRECOVER, from a secp256k1 signature generated and verified by
 * `scratchpad/gen_vectors.py` over raw curve arithmetic - not copied from any
 * published test set. The generator checks the verification equation AND runs
 * the recovery algorithm itself, so a wrong signature could not have been
 * emitted. Recovers 0xf1985e0f473909e46899f098eaac1b92b2cb989e.
 *
 * This matters more here than elsewhere: a malformed signature makes the
 * precompile return empty after failing the range checks, which still charges
 * the flat 3000 gas. Measuring that prices the rejection, not the recovery.
 */
const ECRECOVER_VECTOR =
  '9030a7b7b5c7ff1a844d0e2f351eeeeb6f20ecc55e1f2b64dcedbbc1b6e3d75c'
  + '000000000000000000000000000000000000000000000000000000000000001c'
  + '373da4e8dc818a7842616cbdb7ddd0c9bebc6a4141e8f40753e075cbde074464'
  + '3c2b02c52488328b77de9eab6468bcc10da5abfaeedac52ef4a920e8b29fe6c7'

/**
 * P256VERIFY (EIP-7951), likewise generated and verified from scratch: a
 * NIST P-256 signature over the same message, low-s normalised, with the public
 * key that satisfies it. 160 bytes: hash, r, s, qx, qy.
 */
const P256VERIFY_VECTOR =
  '681cbd59d1e90785efb85b9542e1f3897539e09dcf841401eb15e020e091c978'
  + '8120a8ea087514b530dc5b2633c2ec84d9472e1fa0a81dea4cef198a425d8e12'
  + '3fc71cddc09260412c322ebc4cc3b078a310d65f19ee340f9530743fbbd52845'
  + 'fd85ae13c327172ba80e336cba544d787fd65676bb3f9b58a2c62e0acb0696ad'
  + '63979b4471783b658d6475138bd6d6f9bf42171b4026ad3a32bb22c7bf38c2b0'

/**
 * MODEXP with a full 256-bit exponent modulo the secp256k1 prime.
 *
 * Cost is driven by the exponent's bit length and the modulus width, and the
 * top exponent bit is forced set so the length is exactly 256 - a zero
 * exponent, which is what the zeroed sweep supplied, returns immediately.
 */
const MODEXP_32_VECTOR =
  '0000000000000000000000000000000000000000000000000000000000000020'
  + '0000000000000000000000000000000000000000000000000000000000000020'
  + '0000000000000000000000000000000000000000000000000000000000000020'
  + '0a1289143558c49d48c845f6a23e09d37ef5ce2956d662a1cba6b2c5eab62dd6'
  + 'ffb6523976da61c88b5a82c9d5dc89f199bca0a2012dac5dfaa2ad61fe32a1d3'
  + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'

/** A precompile row: which address, what input, and how it is labelled. */
export interface PrecompileVector {
  readonly address: number
  readonly name: string
  readonly input: string
  readonly note?: string
}

/** The rows that need a real vector. Everything else sweeps with zero bytes. */
export const VECTOR_ROWS: readonly PrecompileVector[] = [
  { address: 0x01, name: 'ECRECOVER', input: ECRECOVER_VECTOR, note: 'real signature; a bad one prices the range check' },
  { address: 0x05, name: 'MODEXP_32', input: MODEXP_32_VECTOR, note: '32-byte base/exp/mod, exponent bit length 256' },
  { address: 0x06, name: 'BN254_ADD', input: bn254G1(0) + bn254G1(1) },
  { address: 0x07, name: 'BN254_MUL', input: bn254G1(0) + BN254_SCALAR_MAX },
  { address: 0x08, name: 'BN254_PAIRING_k1', input: bn254Pairing(1) },
  { address: 0x08, name: 'BN254_PAIRING_k2', input: bn254Pairing(2) },
  { address: 0x08, name: 'BN254_PAIRING_k4', input: bn254Pairing(4) },
  { address: 0x09, name: 'BLAKE2F_r1', input: blake2f(1) },
  { address: 0x09, name: 'BLAKE2F_r12', input: blake2f(12) },
  { address: 0x09, name: 'BLAKE2F_r256', input: blake2f(256) },
  { address: 0x09, name: 'BLAKE2F_r4096', input: blake2f(4096) },
  { address: 0x0a, name: 'POINT_EVALUATION', input: KZG_POINT_EVALUATION, note: 'flat 50000 gas, no size dimension' },
  { address: 0x0b, name: 'BLS12_G1ADD', input: bls12G1(0) + bls12G1(1) },
  { address: 0x0c, name: 'BLS12_G1MSM_k1', input: bls12G1(0) + BLS12_SCALAR_MAX },
  { address: 0x0c, name: 'BLS12_G1MSM_k2', input: bls12G1(0) + BLS12_SCALAR_MAX + bls12G1(1) + BLS12_SCALAR_MAX },
  { address: 0x0d, name: 'BLS12_G2ADD', input: bls12G2(0) + bls12G2(1) },
  { address: 0x0e, name: 'BLS12_G2MSM_k1', input: bls12G2(0) + BLS12_SCALAR_MAX },
  { address: 0x0e, name: 'BLS12_G2MSM_k2', input: bls12G2(0) + BLS12_SCALAR_MAX + bls12G2(1) + BLS12_SCALAR_MAX },
  { address: 0x0f, name: 'BLS12_PAIRING_k1', input: bls12Pairing(1) },
  { address: 0x0f, name: 'BLS12_PAIRING_k2', input: bls12Pairing(2) },
  // A G1 point's x and y are each a valid padded Fp, so the map inputs come out
  // of the same vector as everything else. A zeroed Fp maps to a fixed point
  // and skips most of the SWU work.
  { address: 0x10, name: 'BLS12_MAP_FP_TO_G1', input: bls12G1(0).slice(0, 64 * 2) },
  { address: 0x11, name: 'BLS12_MAP_FP2_TO_G2', input: bls12G1(0) },
  { address: 0x100, name: 'P256VERIFY', input: P256VERIFY_VECTOR, note: 'real NIST P-256 signature, low-s' },
]
