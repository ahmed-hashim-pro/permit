// Synthetic fixture for permit's tests. Inert. 1.3.0 is just faster.
module.exports = function leftPad (str, len, ch) {
  str = String(str)
  ch = ch === undefined || ch === '' ? ' ' : String(ch)
  const need = len - str.length
  return need > 0 ? ch.repeat(Math.ceil(need / ch.length)).slice(0, need) + str : str
}
