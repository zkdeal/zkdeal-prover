/** Pure encoding helpers for the certified AMM execution fixture.
 *
 * Constructor calldata, 32-byte word padding, the RLP list hash behind the raw
 * transaction commitment and the Solidity mapping slot derivation. Nothing here
 * touches the VM or the filesystem.
 */

import {
  padAddress,
  padUint256,
  type Hex,
} from '../../../../app-node/packages/l2-engine/src/index.js'
import {
  bytesToHex0x,
  concatBytes,
  hexToBytes,
  keccak256,
} from '../../../../app-node/packages/protocol/src/index.js'

export const ETH = 10n ** 18n

export function word(value: bigint): string {
  return value.toString(16).padStart(64, '0')
}

export function addressWord(address: Hex): string {
  return address.slice(2).padStart(64, '0')
}

export function stringTail(value: string): string {
  const bytes = new TextEncoder().encode(value)
  const data = Buffer.from(bytes).toString('hex').padEnd(Math.ceil(bytes.length / 32) * 64, '0')
  return `${word(BigInt(bytes.length))}${data}`
}

export function tokenCreation(base: Hex, name: string, symbol: string, holder: Hex): Hex {
  const nameTail = stringTail(name)
  const symbolTail = stringTail(symbol)
  const headBytes = 4n * 32n
  const symbolOffset = headBytes + BigInt(nameTail.length / 2)
  const args = `${word(headBytes)}${word(symbolOffset)}${word(200_000n * ETH)}${addressWord(holder)}${nameTail}${symbolTail}`
  return `${base}${args}` as Hex
}

export function ammCreation(base: Hex, token0: Hex, token1: Hex): Hex {
  return `${base}${addressWord(token0)}${addressWord(token1)}` as Hex
}

export function pad32(value: string | bigint): Hex {
  const body = typeof value === 'bigint' ? value.toString(16) : value.replace(/^0x/, '')
  return `0x${body.padStart(64, '0')}` as Hex
}

export function rlpHashList(hashes: Uint8Array[]): Uint8Array {
  const payload = concatBytes(...hashes.map((hash) => concatBytes(new Uint8Array([0xa0]), hash)))
  if (payload.length <= 55) return concatBytes(new Uint8Array([0xc0 + payload.length]), payload)
  const lengthBytes: number[] = []
  for (let length = payload.length; length > 0; length >>= 8) lengthBytes.unshift(length & 0xff)
  return concatBytes(new Uint8Array([0xf7 + lengthBytes.length, ...lengthBytes]), payload)
}

export function rawTxCommitment(rawTxs: Hex[]): Hex {
  return bytesToHex0x(keccak256(rlpHashList(rawTxs.map((raw) => keccak256(hexToBytes(raw)))))) as Hex
}

export function mappingSlot(address: Hex, slot: bigint): Hex {
  return bytesToHex0x(keccak256(concatBytes(padAddress(address), padUint256(slot)))) as Hex
}
