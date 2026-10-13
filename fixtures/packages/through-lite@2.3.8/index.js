// Synthetic fixture for permit's tests. Inert.
var Stream = require('stream')
module.exports = function through (write, end) {
  var s = new Stream()
  s.readable = s.writable = true
  s.write = function (data) { write.call(s, data); return true }
  s.end = function () { if (end) end.call(s); s.emit('end') }
  return s
}
