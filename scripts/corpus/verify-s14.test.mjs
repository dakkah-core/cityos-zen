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

test('ordering, consent, selectors and time witnesses remain present', () => {
  const ids = fixture.cases.map(scenario => scenario.id)
  assert.equal(new Set(ids).size, ids.length, 'duplicate case IDs')
  for (const id of [
    'first-deny-wins-across-earlier-allow', 'first-allow-wins-in-input-order',
    'later-matching-consent-precedes-earlier-deny', 'granted-consent-exposes-earliest-deny',
    'unmatched-consent-rule-does-not-gate-deny', 'all-six-selectors-match',
    'one-of-six-selectors-mismatch', 'consent-failure-retains-duplicate-rule-ids',
    'policy-expiry-precedes-consent', 'effective-boundary-is-inclusive',
    'action-selector-mismatch', 'purpose-selector-mismatch',
    'resource-type-selector-mismatch', 'subject-selector-mismatch', 'tenant-rule-mismatch',
    'legacy-invalid-consent-expiry', 'invalid-clock',
  ]) assert.ok(ids.includes(id), `missing required S14 witness: ${id}`)
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
    assert.ok(Array.isArray(scenario.expectedIssues), `missing expected issues: ${scenario.id}`)
    assert.deepEqual(result, {
      ok: scenario.expected.effect === 'allow',
      receipt: {
        decisionId: `policy:${input.request.requestId}:${scenario.expected.effect}`,
        effect: scenario.expected.effect,
        policyVersion: input.snapshot.policyVersion,
        requestId: input.request.requestId,
        correlationId: input.request.correlationId,
        evaluatedAt: input.currentTime,
        matchedRuleIds: scenario.expected.matchedRuleIds,
        reasonCodes: scenario.expected.reasonCodes,
      },
      issues: scenario.expectedIssues,
    })
  })
}
