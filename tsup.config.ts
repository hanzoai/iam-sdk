import { defineConfig } from 'tsup'

// Optional peer deps that consumers install themselves — keep them as
// runtime requires so tsup doesn't attempt to bundle them.
//
// Note: `passport-oauth2` is intentionally NOT external. Marking it
// external makes tsup emit `__require("passport-oauth2")` (a dynamic
// require wrapper for ESM/CJS compat), which downstream bundlers like
// esbuild can't statically resolve. The team monorepo bundles every
// pod's __start.ts via esbuild and ships a single bundle.js without a
// runtime node_modules — `__require("passport-oauth2")` then fails at
// startup with MODULE_NOT_FOUND. Letting tsup bundle passport-oauth2
// into the SDK's dist (via a static `import OAuth2Strategy from
// "passport-oauth2"` in src/passport.ts) lets the downstream bundler
// inline it through normal static resolution.
const optionalPeers = [
  'react',
  'react-dom',
  'next',
  'next-auth',
  'better-auth',
  'passport'
]

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/paths.ts',
    'src/auth.ts',
    'src/browser.ts',
    'src/session.ts',
    'src/server.ts',
    'src/types.ts',
    'src/react.ts',
    'src/views.tsx',
    'src/nextauth.ts',
    'src/sveltekit.ts',
    'src/remix.ts',
    'src/express.ts',
    'src/hono.ts',
    'src/passport.ts',
    'src/betterauth.ts',
    'src/validation.ts'
  ],
  format: ['esm', 'cjs'],
  // Declarations come from tsc (tsconfig.build.json), not tsup's dts
  // plugin: that plugin sets `baseUrl` on every build, and TypeScript 6+
  // rejects the option (TS5101).
  onSuccess: 'tsc -p tsconfig.build.json',
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  target: 'es2022',
  outDir: 'dist',
  external: optionalPeers
})
