/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// solidWalkJS uses Solid's $DEVCOMP global registry of mounted components.
// Returns null when not in dev/instrumented mode.
const solidWalkJS = `(function(){
  try {
    var reg = window.$DEVCOMP || (window.Solid$$ && window.Solid$$.$DEVCOMP);
    if (!reg) return null;
    var nodeCount = 0;
    var MAX_NODES = 100000;
    var MAX_DEPTH = 1000;
    function walk(c, depth) {
      if (!c || depth > MAX_DEPTH || nodeCount >= MAX_NODES) return null;
      nodeCount++;
      var name = (c.componentName) || (c.fn && c.fn.name) || (c.name) || "Component";
      var node = { name: String(name), children: [] };
      var ch = c.children || c.owned || [];
      for (var i = 0; i < ch.length; i++) {
        var w = walk(ch[i], depth + 1);
        if (w) node.children.push(w);
      }
      return node;
    }
    var roots = [];
    if (typeof reg.forEach === "function") {
      reg.forEach(function(c){ var w = walk(c, 0); if (w) roots.push(w); });
    } else {
      for (var k in reg) { var w = walk(reg[k], 0); if (w) roots.push(w); }
    }
    return roots.length ? roots : null;
  } catch(e) { return null; }
})()`

func extractSolidTree(ctx context.Context, c *cdp.Client) (*FrameworkTree, error) {
	raw, err := c.Eval(ctx, solidWalkJS, cdp.EvalOpts{})
	if err != nil {
		return nil, err
	}
	return decodeFrameworkTree(raw)
}
