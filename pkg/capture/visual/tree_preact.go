/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// preactWalkJS uses Preact's __PREACT_DEVTOOLS__ hook. Returns null when
// devtools-bridge is not installed.
const preactWalkJS = `(function(){
  try {
    var hook = window.__PREACT_DEVTOOLS__;
    if (!hook) return null;
    var nodeCount = 0;
    var MAX_NODES = 100000;
    var MAX_DEPTH = 1000;
    function walk(vnode, depth) {
      if (!vnode || depth > MAX_DEPTH || nodeCount >= MAX_NODES) return null;
      nodeCount++;
      var t = vnode.type;
      var name = (typeof t === "string") ? t : (t && (t.displayName || t.name)) || "Anonymous";
      var node = { name: String(name), children: [] };
      var kids = vnode._children || vnode.__k || [];
      for (var i = 0; i < kids.length; i++) {
        var w = walk(kids[i], depth + 1);
        if (w) node.children.push(w);
      }
      return node;
    }
    var roots = (hook.roots && (hook.roots.values ? Array.from(hook.roots.values()) : hook.roots)) || [];
    var out = [];
    for (var i = 0; i < roots.length; i++) {
      var w = walk(roots[i], 0);
      if (w) out.push(w);
    }
    return out.length ? out : null;
  } catch(e) { return null; }
})()`

func extractPreactTree(ctx context.Context, c *cdp.Client) (*FrameworkTree, error) {
	raw, err := c.Eval(ctx, preactWalkJS, cdp.EvalOpts{})
	if err != nil {
		return nil, err
	}
	return decodeFrameworkTree(raw)
}
