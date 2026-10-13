// Synthetic fixture for permit's tests, modelled on esbuild's install step,
// which checks that the platform binary is in place. Inert.
const fs = require('fs')
const path = require('path')
const bin = path.join(__dirname, 'bin', 'fast-bundler')
if (!fs.existsSync(bin)) {
  console.error('fast-bundler: no binary for ' + process.platform)
  process.exitCode = 1
}
