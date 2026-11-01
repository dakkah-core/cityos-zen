// Run from the CMS checkout after selecting its canonical Node toolchain.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { test } from 'node:test'
import { pathToFileURL } from 'node:url'

const fixture = JSON.parse(await readFile(new URL('../../extensions/cityos/corpus/s14-decision-baseline.json', import.meta.url), 'utf8'))
const cms = resolve(process.env.CITYOS_CMS_ROOT ?? process.cwd())
const git = (...args) => execFileSync('git', ['-C', cms, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()

function merge(base, override) {
  for (const [key, value] of Object.entries(override)) {
    if (value && typeof value === 'object' && !Array.isArray(value) && base[key] && typeof base[key] === 'object' && !Array.isArray(base[key])) {
      merge(base[key], value)
    } else base[key] = structuredClone(value)
  }
  return base
}

test('characterization source is the recorded, unmodified CMS blob', () => {
  assert.equal(git('rev-parse', `HEAD:${fixture.source.path}`), fixture.source.gitBlob)
  assert.equal(git('status', '--porcelain=v1', '--', fixture.source.path), '')
})

const { resolveSharedPolicyDecision } = await import(pathToFileURL(resolve(cms, fixture.source.path)).href)
for (const scenario of fixture.cases) {
  test(`S14 synthetic baseline: ${scenario.id}`, () => {
    const input = merge(structuredClone(fixture.baseInput), scenario.override)
    const result = resolveSharedPolicyDecision(input)
    assert.deepEqual({
      effect: result.receipt.effect,
      reasonCodes: result.receipt.reasonCodes,
      matchedRuleIds: result.receipt.matchedRuleIds,
    }, scenario.expected)
  })
}
