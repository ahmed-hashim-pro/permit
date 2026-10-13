// Synthetic fixture for permit's tests, modelled on esbuild. Inert.
const path = require('path')
const fs = require('fs')
exports.build = function build (opts) {
  const code = fs.readFileSync(opts.entry, 'utf8')
  fs.writeFileSync(path.resolve(opts.outfile), code)
}
