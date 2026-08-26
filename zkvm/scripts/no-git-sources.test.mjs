import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

test('release sources require no repository client', () => {
  const result = spawnSync(process.execPath, [join(here, 'check-no-git-sources.mjs')], {
    encoding: 'utf8',
  })
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /gate passed/)
})

test('gate scans nested first-party commands, package scripts, and Cargo sources', () => {
  const root = mkdtempSync(join(tmpdir(), 'zkdeal-no-repository-client-'))
  try {
    mkdirSync(join(root, 'nested'), { recursive: true })
    writeFileSync(
      join(root, 'package.json'),
      JSON.stringify({ scripts: { unsafe: ['gi', 't status'].join('') } }),
    )
    writeFileSync(join(root, 'nested', 'Dockerfile'), 'RUN echo safe\n')
    writeFileSync(
      join(root, 'nested', 'Cargo.toml'),
      '[dependencies]\nunsafe = { git = "https://invalid.example/repository" }\n',
    )
    const result = spawnSync(process.execPath, [join(here, 'check-no-git-sources.mjs')], {
      encoding: 'utf8',
      env: { ...process.env, ZKDEAL_NO_GIT_SCAN_ROOT: root },
    })
    assert.equal(result.status, 1)
    assert.match(result.stderr, /package\.json contains a forbidden repository command/)
    assert.match(result.stderr, /Cargo\.toml contains a repository dependency source/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
