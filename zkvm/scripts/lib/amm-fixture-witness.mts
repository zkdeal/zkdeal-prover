/** Witness shaping for the certified AMM execution fixture.
 *
 * Turns the engine's state dumps into the slot-keyed pre/post state the Rust
 * STF test reads, materializes the full-room-state-v1 compact witness, and
 * derives the storage leaves the guest's exit program is guaranteed to read.
 */

import type { buildGenesis, Hex } from '../../../../app-node/packages/l2-engine/src/index.js'
import {
  bytesToHex0x,
  hexToBytes,
} from '../../../../app-node/packages/protocol/src/index.js'

import { mappingSlot, pad32 } from './amm-fixture-encoding.mjs'
import { U } from './ethereumjs-util.mjs'

export type DumpAccount = {
  nonce: string
  balance: string
  code?: Hex
  storage: Record<string, Hex>
}

export type RoomEngine = Awaited<ReturnType<typeof buildGenesis>>['engine']

export function fixtureState(raw: string) {
  const dump = JSON.parse(raw) as Record<string, DumpAccount>
  return Object.entries(dump)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([address, account]) => ({
      address,
      nonce: `0x${BigInt(account.nonce).toString(16)}`,
      balance: `0x${BigInt(account.balance).toString(16)}`,
      ...(account.code ? { code: account.code } : {}),
      storage: Object.fromEntries(
        Object.entries(account.storage)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([slot, value]) => [pad32(slot), pad32(value)]),
      ),
    }))
}

export function parsedStateDump(raw: string): Record<string, DumpAccount> {
  return Object.fromEntries(
    Object.entries(JSON.parse(raw) as Record<string, DumpAccount>)
      .map(([address, account]) => [address.toLowerCase(), account]),
  )
}

/**
 * Materialize the exact full-room-state-v1 witness used by the batch test.
 * The executed engine contributes the complete discovered access envelope;
 * the freshly rebuilt genesis engine contributes pre-transaction values.
 */
export async function compactStateV4(
  prestateEngine: RoomEngine,
  accessEngine: RoomEngine,
  requiredAddresses: readonly Hex[],
  requiredStorage: ReadonlyMap<string, ReadonlySet<Hex>> = new Map(),
) {
  await prestateEngine.stateManager.flush()
  const dump = parsedStateDump(await prestateEngine.captureWitnessStateJson())
  const accessDump = parsedStateDump(await accessEngine.captureWitnessStateJson())
  const addresses = new Set([
    ...Object.keys(dump),
    ...Object.keys(accessDump),
    ...requiredAddresses.map((address) => address.toLowerCase()),
    `0x${'00'.repeat(20)}`,
  ])
  const accounts = []
  for (const address of [...addresses].sort()) {
    const entry = dump[address]
    if (!entry) {
      accounts.push({
        address,
        exists: false,
        nonce: '0',
        balance: pad32('0x0'),
        code: '0x',
        canonicalStorageRoot: bytesToHex0x(U.KECCAK256_RLP),
        accountProof: [],
        storage: [],
      })
      continue
    }
    const evmAddress = U.createAddressFromString(address)
    const account = await prestateEngine.stateManager.getAccount(evmAddress)
    if (!account) throw new Error(`AMM prestate account disappeared: ${address}`)
    const slots = new Set([
      ...Object.keys(entry.storage).map((slot) => pad32(slot).toLowerCase()),
      ...prestateEngine.slotBook.slotsFor(address).map((slot) => pad32(slot).toLowerCase()),
      ...accessEngine.slotBook.slotsFor(address).map((slot) => pad32(slot).toLowerCase()),
      ...[...(requiredStorage.get(address) ?? [])].map((slot) => pad32(slot).toLowerCase()),
    ])
    const storage = []
    for (const slot of [...slots].sort()) {
      const value = await prestateEngine.stateManager.getStorage(evmAddress, hexToBytes(slot))
      storage.push({
        slot,
        value: value.length === 0 ? pad32('0x0') : pad32(bytesToHex0x(value)),
        proof: [],
      })
    }
    accounts.push({
      address,
      exists: true,
      nonce: account.nonce.toString(),
      balance: pad32(`0x${account.balance.toString(16)}`),
      code: entry.code ?? '0x',
      canonicalStorageRoot: bytesToHex0x(account.storageRoot),
      accountProof: [],
      storage,
    })
  }
  return { canonicalStateRoot: pad32('0x0'), accounts }
}

export type ExitProgramStorageV4 = {
  assets: Array<{
    assetId: number
    kind: string
    token?: Hex
    balanceSlot?: string
    totalSupplySlot?: string
  }>
  positions: Array<{
    contract: Hex
    shareBalanceSlot: string
    totalSupplySlot: string
    excludedShareAccounts: Hex[]
    backings: Array<{ assetId: number; reserveSlot?: string }>
  }>
}

/** Every leaf read by the guest's exit program is part of the batch witness,
 * including zero-valued mapping leaves never touched by transaction replay. */
export function exitProgramStorage(
  program: ExitProgramStorageV4,
  members: readonly Hex[],
): Map<string, Set<Hex>> {
  const required = new Map<string, Set<Hex>>()
  const add = (address: Hex, slot: Hex | bigint) => {
    const key = address.toLowerCase()
    const slots = required.get(key) ?? new Set<Hex>()
    slots.add(typeof slot === 'bigint' ? pad32(slot) : pad32(slot))
    required.set(key, slots)
  }
  const erc20 = new Map<number, { token: Hex; balanceSlot: bigint }>()
  for (const asset of program.assets) {
    if (asset.kind !== 'erc20' || !asset.token || asset.balanceSlot === undefined) continue
    const balanceSlot = BigInt(asset.balanceSlot)
    const totalSupplySlot = BigInt(asset.totalSupplySlot ?? '0')
    add(asset.token, totalSupplySlot)
    for (const member of members) add(asset.token, mappingSlot(member, balanceSlot))
    erc20.set(asset.assetId, { token: asset.token, balanceSlot })
  }
  for (const position of program.positions) {
    const shareSlot = BigInt(position.shareBalanceSlot)
    add(position.contract, BigInt(position.totalSupplySlot))
    for (const member of members) add(position.contract, mappingSlot(member, shareSlot))
    for (const excluded of position.excludedShareAccounts) {
      add(position.contract, mappingSlot(excluded, shareSlot))
    }
    for (const backing of position.backings) {
      const asset = erc20.get(backing.assetId)
      if (!asset) throw new Error(`exit position references unknown ERC-20 asset ${backing.assetId}`)
      add(asset.token, mappingSlot(position.contract, asset.balanceSlot))
      if (backing.reserveSlot !== undefined) add(position.contract, BigInt(backing.reserveSlot))
    }
  }
  return required
}
