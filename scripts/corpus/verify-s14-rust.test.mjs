// Explicitly compare a local Rust preview executable with the shared corpus.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'

const fixture = JSON.parse(await readFile(new URL('../../extensions/cityos/corpus/s14-decision-baseline.json', import.meta.url), 'utf8'))
const binary = process.env.CITYOS_S14_PREVIEW_BIN
if (!binary) throw new Error('CITYOS_S14_PREVIEW_BIN must name the built Rust preview executable')

function merge(base, override) {
  for (const [key, value] of Object.entries(override)) {
    if (value && typeof value === 'object' && !Array.isArray(value) && base[key] && typeof base[key] === 'object' && !Array.isArray(base[key])) {
      merge(base[key], value)
    } else base[key] = structuredClone(value)
  }
  return base
}

const unsupported = new Set(['invalid-clock', 'legacy-invalid-consent-expiry'])
for (const scenario of fixture.cases) {
  test(`Rust S14 preview: ${scenario.id}`, () => {
    const input = merge(structuredClone(fixture.baseInput), scenario.override)
    const output = JSON.parse(execFileSync(binary, [], { input: JSON.stringify(input), encoding: 'utf8', timeout: 15000, maxBuffer: 65536 }))
    assert.equal(output.kind, 'preview')
    assert.equal(output.profile, 'cityos.shared-policy.strict-utc-preview.v1')
    if (unsupported.has(scenario.id)) {
      assert.equal(output.status, 'unsupported')
      assert.equal(output.reason, 'timestamp is not within the supported strict UTC profile')
    } else {
      assert.equal(output.status, 'ok')
      assert.deepEqual(output.decision, scenario.expected)
    }
  })
}
