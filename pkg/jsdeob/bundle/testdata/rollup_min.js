// FIXTURE: synthetic Rollup standalone UMD output.
// Provenance: typeof define === 'function' && define.amd / typeof exports === 'object'
// are stable Rollup UMD preamble markers.
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
  typeof define === 'function' && define.amd ? define(['exports'], factory) :
  (global = global || self, factory(global.MyLib = {}));
}(this, (function (exports) {
  'use strict';
  function add(a, b) { return a + b; }
  exports.add = add;
})));
