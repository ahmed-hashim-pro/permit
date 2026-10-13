// Synthetic fixture for permit's tests, modelled on ua-parser-js. Inert.
var BROWSERS = [[/(edg)\/([\w.]+)/i, "Edge"], [/(firefox)\/([\w.]+)/i, "Firefox"], [/(chrome)\/([\w.]+)/i, "Chrome"]]
module.exports = function parse (ua) {
  for (var i = 0; i < BROWSERS.length; i++) {
    var m = BROWSERS[i][0].exec(ua)
    if (m) return { name: BROWSERS[i][1], version: m[2] }
  }
  return { name: undefined, version: undefined }
}
