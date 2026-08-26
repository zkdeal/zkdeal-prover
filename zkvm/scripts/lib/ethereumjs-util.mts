/** Load @ethereumjs/util through the l2-engine package so the fixture
 * generators observe exactly the resolution the engine itself uses.
 *
 * The generators need `U` in two places — address derivation in the driver and
 * account/storage shaping in the witness builder — so the dynamic import lives
 * here once rather than being repeated per module.
 */

import { dirname, join, resolve } from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
export const repoRoot = resolve(here, '..', '..', '..')

const engineRequire = createRequire(join(repoRoot, 'packages', 'l2-engine', 'package.json'))
const utilPath = engineRequire.resolve('@ethereumjs/util')
export const U: typeof import('@ethereumjs/util') = await import(pathToFileURL(utilPath).href)
