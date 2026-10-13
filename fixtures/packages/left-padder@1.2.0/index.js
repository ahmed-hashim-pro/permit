// Synthetic fixture for permit's tests. Inert.
module.exports = function leftPad (str, len, ch) {
  str = String(str)
  ch = ch === undefined ? ' ' : String(ch)
  while (str.length < len) str = ch + str
  return str
}
