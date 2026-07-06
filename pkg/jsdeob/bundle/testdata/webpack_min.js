// FIXTURE: synthetic webpack chunked-array bundle.
// Provenance: shape mirrors `(self.webpackChunk_my_app=...||[]).push([[id],{modules}])`
// per webpack runtime layout. __webpack_require__.d call recovers name "Foo".
(self.webpackChunk_my_app = self.webpackChunk_my_app || []).push([[123], {
  456: function (e, t, r) {
    "use strict";
    var Foo = function () { return 1 };
    r.d(t, { Foo: function () { return Foo } });
  },
  789: function (module, exports) {
    exports.bar = "baz";
  }
}]);
__webpack_require__.d(t, { Foo: function () { return Foo } });
