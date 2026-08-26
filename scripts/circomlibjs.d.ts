/** Minimal type surface for circomlibjs, which does not publish TypeScript declarations. */
declare module 'circomlibjs' {
  export interface FField {
    p: bigint
    toObject(value: unknown): bigint
    e(value: bigint | number | string): unknown
    eq(a: unknown, b: unknown): boolean
  }

  export interface Poseidon {
    (inputs: ReadonlyArray<bigint | number | string | unknown>, initState?: unknown): unknown
    F: FField
  }

  export interface EddsaSignature {
    R8: [unknown, unknown]
    S: bigint
  }

  export interface Eddsa {
    prv2pub(privateKey: Uint8Array): [unknown, unknown]
    signPoseidon(privateKey: Uint8Array, message: unknown): EddsaSignature
    verifyPoseidon(message: unknown, signature: EddsaSignature, publicKey: [unknown, unknown]): boolean
    F: FField
  }

  export function buildPoseidon(): Promise<Poseidon>
  export function buildEddsa(): Promise<Eddsa>
}
