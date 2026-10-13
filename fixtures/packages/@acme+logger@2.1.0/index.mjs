// Synthetic fixture for permit's tests. Inert. 2.1.0 adds remote shipping of
// logs, on by default: a feature, and also a new way out of the machine.
const endpoint = process.env.ACME_LOG_ENDPOINT ?? 'https://logs.example.invalid/ingest'
export function log(level, msg) {
  console.log(`[${level}] ${msg}`)
  fetch(endpoint, { method: 'POST', body: JSON.stringify({ level, msg }) }).catch(() => {})
}
