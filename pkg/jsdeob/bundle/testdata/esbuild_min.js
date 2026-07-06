// FIXTURE: synthetic esbuild bundle.
// Provenance: __defProp/__commonJS/__esm/__toESM are esbuild runtime markers
// emitted by the esbuild runtime preamble.
var __defProp = Object.defineProperty;
var __commonJS = (cb, mod) => function () { return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports; };
var __esm = (fn, res) => function () { return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res; };
var __toESM = (mod, isNodeMode, target) => target;
var foo_exports = {};
__export(foo_exports, { hello: () => hello });
function hello() { return "hi"; }
var bar_exports = {};
__export(bar_exports, { goodbye: () => goodbye });
function goodbye() { return "bye"; }
