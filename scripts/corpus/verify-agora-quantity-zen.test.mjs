// Synthetic source-local lowering -> Zen preview. The supplied authorization
// bit is test data; this does not issue a receipt or commit an owner effect.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'

const base = new URL('../../extensions/cityos/corpus/', import.meta.url)
const corpus = JSON.parse(await readFile(new URL('agora-cart-baseline.json', base), 'utf8'))
const source = await readFile(new URL('cart-quantity-preview.json', base), 'utf8')
const sourceSha256 = createHash('sha256').update(source).digest('hex')
const lowerer = process.env.CITYOS_AGORA_QUANTITY_PREVIEW_BIN
const worker = process.env.CITYOS_ZEN_PREVIEW_WORKER_BIN
if (!lowerer || !worker) throw new Error('Both synthetic preview executables must be identified explicitly')

const cases = corpus.cases.filter(scenario => scenario.expected.outcome === 'evaluated'
  && scenario.rules.length === 1 && scenario.rules[0].template === 'maximum')
if (!cases.length) throw new Error('No quantity cases in the identified corpus')
for (const scenario of cases) {
  test(`Synthetic Agora quantity through Zen: ${scenario.id}`, () => {
    const rule = { ...corpus.ruleTemplates.maximum, ...scenario.rules[0].override }
    const input = {
      items: scenario.body.items.map(item => ({ sku: item.sku, quantity: item.quantity ?? null })),
      rule: { active: rule.status === 'active', targetSku: rule.targetSku ?? null, maxQuantity: rule.maxQuantity ?? null },
    }
    const facts = JSON.parse(execFileSync(lowerer, [], { input: JSON.stringify(input), encoding: 'utf8', timeout: 15000, maxBuffer: 65536 }))
    assert.equal(facts.kind, 'preview')
    for (const authorized of [true, false]) {
      const request = { kind: 'preview', source, facts: { quantity: facts.quantity, maxQuantity: facts.maxQuantity, authorized } }
      const output = JSON.parse(execFileSync(worker, ['--preview-stdio'], { input: JSON.stringify(request), encoding: 'utf8', timeout: 15000, maxBuffer: 65536 }))
      assert.deepEqual(output, { kind: 'preview', allowed: authorized && scenario.expected.allowed,
        sourceSha256, profile: 'cityos.zen.cart-quantity-preview.v1' })
    }
  })
}
