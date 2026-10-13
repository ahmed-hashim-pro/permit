// Synthetic fixture for permit's tests, modelled on event-stream 3.3.5. Inert.
var through = require('through-lite')
var Stream = require('stream').Stream

exports.through = through
exports.pipeline = function () {
  var streams = [].slice.call(arguments)
  return streams.reduce(function (a, b) { return a.pipe(b) })
}
exports.isStream = function (s) { return s instanceof Stream }
