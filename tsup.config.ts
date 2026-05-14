import { defineConfig } from 'tsup'

// Optional peer deps that consumers install themselves — keep them as
// runtime requires so tsup doesn't attempt to bundle them.
const optionalPeers = [
  'react',
  'react-dom',
  'next',
  'next-auth',
  'better-auth',
  'passport',
  'passport-oauth2'
]

export default defineConfig({
  entry: [
    'src/index.ts',
    'src/auth.ts',
    'src/browser.ts',
    'src/billing.ts',
    'src/types.ts',
    'src/react.ts',
    'src/nextauth.ts',
    'src/passport.ts',
    'src/betterauth.ts'
  ],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  target: 'es2022',
  outDir: 'dist',
  external: optionalPeers
})
