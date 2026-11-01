import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { test } from 'node:test'

const baseline = JSON.parse(await readFile(new URL('../../extensions/cityos/corpus/receipt-source-baseline.json', import.meta.url), 'utf8'))
const cms = resolve(process.env.CITYOS_CMS_ROOT ?? process.cwd())
const git = (...args) => execFileSync('git', ['-C', cms, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()

for (const source of baseline.sources) {
  test(`receipt baseline source: ${source.path}`, () => {
    assert.equal(git('rev-parse', `HEAD:${source.path}`), source.gitBlob)
    assert.equal(git('status', '--porcelain=v1', '--', source.path), '')
  })
}
