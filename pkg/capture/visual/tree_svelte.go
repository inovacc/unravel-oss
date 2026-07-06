/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// svelteWalkJS uses __SVELTE_DEVTOOLS_GLOBAL_HOOK__ when present. Production
// Svelte builds typically lack this hook → returns null and the orchestrator
// falls back to tree.json only (RESEARCH §Svelte fallback rule).
const svelteWalkJS = `(function(){
  try {
    var hook = window.__SVELTE_DEVTOOLS_GLOBAL_HOOK__;
    if (!hook || typeof hook.getRoots !== "function") return null;
    var nodeCount = 0;
    var MAX_NODES = 100000;
    var MAX_DEPTH = 1000;
    function walk(c, depth) {
      if (!c || depth > MAX_DEPTH || nodeCount >= MAX_NODES) return null;
      nodeCount++;
      var name = (c.tagName) || (c.ctor && c.ctor.name) || "Component";
      var node = { name: String(name), children: [] };
      var ch = c.children || [];
      for (var i = 0; i < ch.length; i++) {
        var w = walk(ch[i], depth + 1);
        if (w) node.children.push(w);
      }
      return node;
    }
    var roots = hook.getRoots() || [];
    var out = [];
    for (var i = 0; i < roots.length; i++) {
      var w = walk(roots[i], 0);
      if (w) out.push(w);
    }
    return out.length ? out : null;
  } catch(e) { return null; }
})()`

func extractSvelteTree(ctx context.Context, c *cdp.Client) (*FrameworkTree, error) {
	raw, err := c.Eval(ctx, svelteWalkJS, cdp.EvalOpts{})
	if err != nil {
		return nil, err
	}
	return decodeFrameworkTree(raw)
}
