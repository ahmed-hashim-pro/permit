// Synthetic fixture for permit's tests, modelled on event-stream 3.3.6. Inert.
var through = require('through-lite')
var flatmap = require('flatmap-lite')
var Stream = require('stream').Stream

exports.through = through
exports.flatmapSync = flatmap
exports.pipeline = function () {
  var streams = [].slice.call(arguments)
  return streams.reduce(function (a, b) { return a.pipe(b) })
}
exports.isStream = function (s) { return s instanceof Stream }
