// Invoke with the CMS Agora Vitest configuration and CITYOS_CMS_ROOT set.
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const cms = process.env.CITYOS_CMS_ROOT
if (!cms) throw new Error('CITYOS_CMS_ROOT is required for Agora source characterization')
const corpus = JSON.parse(readFileSync(new URL('../../extensions/cityos/corpus/agora-cart-baseline.json', import.meta.url), 'utf8'))
const source = resolve(cms, corpus.source.path)
const git = (...args: string[]) => execFileSync('git', ['-C', cms, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
const { evaluateAgoraCartRules } = await import(source)

describe('Agora cart source characterization', () => {
  it('uses the recorded unmodified owner source', () => {
    expect(git('rev-parse', `HEAD:${corpus.source.path}`)).toBe(corpus.source.gitBlob)
    expect(git('status', '--porcelain=v1', '--', corpus.source.path)).toBe('')
  })
  for (const scenario of corpus.cases) {
    it(scenario.id, async () => {
      const rules = scenario.rules.map((rule: { template: string; override?: Record<string, unknown> }) => ({
        ...structuredClone(corpus.ruleTemplates[rule.template]), ...rule.override,
      }))
      const result = await evaluateAgoraCartRules({
        tenantId: scenario.tenantId, readBody: async () => structuredClone(scenario.body),
      }, { listCartRules: async () => rules })
      const projection = result.outcome === 'evaluated'
        ? { outcome: result.outcome, allowed: result.evaluation.allowed, subtotalHalalas: result.evaluation.subtotalHalalas,
            violations: result.evaluation.violations.map((rule: { ruleId: string }) => rule.ruleId) }
        : { outcome: result.outcome, code: result.code }
      expect(projection).toEqual(scenario.expected)
    })
  }
})
