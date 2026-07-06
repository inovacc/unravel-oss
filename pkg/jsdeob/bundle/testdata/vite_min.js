// FIXTURE: synthetic Vite production bundle (Rollup-driven).
// Provenance: __vite__mapDeps + __vitePreload are stable Vite runtime markers.
const __vite__mapDeps = (i) => i.map(j => deps[j]);
function __vitePreload(baseModule, deps) { return baseModule(); }
const a = (() => {
  function inner() { return 1 }
  return { inner };
})();
const b = (() => {
  const x = 2;
  return { x };
})();
