import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import {
  canonicalManifest,
  collectSourceManifest,
  sourceManifestSha256,
  verifyCandidateSourceManifest,
} from './check-lock-freshness.mjs'

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'zkdeal-source-manifest-'))
  mkdirSync(join(root, 'src'))
  writeFileSync(join(root, 'src', 'b.rs'), 'b\n')
  writeFileSync(join(root, 'src', 'a.rs'), 'a\n')
  return root
}

test('manifest ordering and digest are deterministic filesystem properties', () => {
  const root = fixture()
  try {
    const first = collectSourceManifest(root, ['src'])
    const second = collectSourceManifest(root, ['src'])
    assert.deepEqual(first.files.map((file) => file.path), ['src/a.rs', 'src/b.rs'])
    assert.equal(canonicalManifest(first), canonicalManifest(second))
    assert.equal(sourceManifestSha256(first), sourceManifestSha256(second))
    assert.match(sourceManifestSha256(first), /^[0-9a-f]{64}$/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('source drift changes the manifest', () => {
  const root = fixture()
  try {
    const before = collectSourceManifest(root, ['src'])
    writeFileSync(join(root, 'src', 'a.rs'), 'changed\n')
    const sourceDrift = collectSourceManifest(root, ['src'])
    assert.notEqual(sourceDrift.filesDigest, before.filesDigest)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('canonical output contains no timestamps or repository-history identity', () => {
  const root = fixture()
  try {
    const text = canonicalManifest(
      collectSourceManifest(root, ['src']),
    )
    assert.doesNotMatch(text, /timestamp|commit|branch|repository/i)
    assert.equal(readFileSync(join(root, 'src', 'a.rs'), 'utf8'), 'a\n')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('sealed candidate build input is checked without rewriting it', () => {
  const root = fixture()
  const candidate = join(root, 'source-manifest.candidate.json')
  try {
    const manifest = collectSourceManifest(root, ['src'])
    writeFileSync(candidate, canonicalManifest(manifest))
    const before = readFileSync(candidate)
    const checked = verifyCandidateSourceManifest(root, candidate, ['src'])
    assert.equal(checked.sha256, sourceManifestSha256(manifest))
    assert.deepEqual(readFileSync(candidate), before)
    writeFileSync(join(root, 'src', 'a.rs'), 'drift\n')
    assert.throws(
      () => verifyCandidateSourceManifest(root, candidate, ['src']),
      /candidate source manifest is stale/,
    )
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
