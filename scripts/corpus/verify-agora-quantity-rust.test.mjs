// Compare the same identified synthetic owner corpus with a local Rust preview.
// This is not an authorization, owner commit or artifact qualification.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'

const corpus = JSON.parse(await readFile(new URL('../../extensions/cityos/corpus/agora-cart-baseline.json', import.meta.url), 'utf8'))
const binary = process.env.CITYOS_AGORA_QUANTITY_PREVIEW_BIN
if (!binary) throw new Error('CITYOS_AGORA_QUANTITY_PREVIEW_BIN must identify the built Rust preview')

const cases = corpus.cases.filter(scenario => scenario.expected.outcome === 'evaluated'
  && scenario.rules.length === 1 && scenario.rules[0].template === 'maximum')
if (cases.length === 0) throw new Error('No quantity cases in the identified corpus')
for (const scenario of cases) {
  test(`Rust quantity lowering: ${scenario.id}`, () => {
    const rule = { ...corpus.ruleTemplates.maximum, ...scenario.rules[0].override }
    const input = {
      items: scenario.body.items.map(item => ({ sku: item.sku, quantity: item.quantity ?? null })),
      rule: { active: rule.status === 'active', targetSku: rule.targetSku ?? null, maxQuantity: rule.maxQuantity ?? null },
    }
    const output = JSON.parse(execFileSync(binary, [], { input: JSON.stringify(input), encoding: 'utf8', timeout: 15000, maxBuffer: 65536 }))
    assert.equal(output.kind, 'preview')
    assert.equal(output.quantity > output.maxQuantity, scenario.expected.violations.includes(rule.ruleId))
  })
}
