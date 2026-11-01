// The checkout can contain ignored stale JS beside authored TS. Characterize
// the authored TS and its source dependencies without rewriting either file.
import { existsSync } from 'node:fs'
import { dirname, resolve, sep } from 'node:path'

const cms = resolve(process.env.CITYOS_CMS_ROOT ?? process.cwd())
const packages = [
  'agora-demand-commitment-domain', 'agora-economic-contracts',
  'shared-policy-contracts', 'shared-policy-domain', 'shared-policy-application',
  'shared-platform-contracts', 'shared-platform-runtime-primitives',
  'shared-policy-capability-pack-contracts', 'shared-policy-capability-pack-runtime-core',
]

export default {
  test: { environment: 'node' },
  resolve: {
    extensions: ['.ts', '.tsx', '.mjs', '.js', '.json'],
    alias: packages.map(name => ({ find: `@cityos/${name}`, replacement: resolve(cms, 'packages', name, 'src/index.ts') })),
  },
  plugins: [{
    name: 'cityos-policy-authored-typescript',
    enforce: 'pre',
    resolveId(source, importer) {
      if (!importer || !source.startsWith('.') || !source.endsWith('.js')) return null
      const origin = importer.split('?')[0]
      if (!origin.startsWith(cms + sep) && !origin.startsWith(cms.replaceAll('\\', '/') + '/')) return null
      const candidate = resolve(dirname(origin), source.slice(0, -3) + '.ts')
      return existsSync(candidate) ? candidate : null
    },
  }],
}
