/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// reactFiberWalkJS is the React devtools-hook fiber-walk payload (RESEARCH
// §"React"). Returns null when the hook is not installed (production builds
// without devtools); returns an array of fiber roots otherwise. The walk caps
// recursion depth at 1000 and total node count at 100,000 (RESEARCH Pitfall
// 3) to prevent walker DoS.
const reactFiberWalkJS = `(function(){
  try {
    var hook = window.__REACT_DEVTOOLS_GLOBAL_HOOK__;
    if (!hook || typeof hook.getFiberRoots !== "function") return null;
    var roots = [];
    var rendererIDs = [];
    if (hook.renderers && typeof hook.renderers.forEach === "function") {
      hook.renderers.forEach(function(_, id){ rendererIDs.push(id); });
    } else if (hook._renderers) {
      for (var k in hook._renderers) rendererIDs.push(k);
    }
    var nodeCount = 0;
    var MAX_NODES = 100000;
    var MAX_DEPTH = 1000;
    function walk(fiber, depth) {
      if (!fiber || depth > MAX_DEPTH || nodeCount >= MAX_NODES) return null;
      nodeCount++;
      var name = "";
      var t = fiber.type;
      if (typeof t === "string") name = t;
      else if (t && t.displayName) name = t.displayName;
      else if (t && t.name) name = t.name;
      else if (fiber.elementType && fiber.elementType.displayName) name = fiber.elementType.displayName;
      else if (fiber.elementType && fiber.elementType.name) name = fiber.elementType.name;
      else name = "Anonymous";
      var node = { name: name, children: [] };
      if (fiber.key != null) node.key = String(fiber.key);
      var child = fiber.child;
      while (child) {
        var c = walk(child, depth + 1);
        if (c) node.children.push(c);
        child = child.sibling;
      }
      return node;
    }
    rendererIDs.forEach(function(id){
      try {
        var rootSet = hook.getFiberRoots(id);
        if (!rootSet) return;
        rootSet.forEach(function(root){
          var rendered = walk(root.current, 0);
          if (rendered) roots.push(rendered);
        });
      } catch (e) { /* skip renderer */ }
    });
    return roots;
  } catch (e) { return null; }
})()`

func extractReactTree(ctx context.Context, c *cdp.Client) (*FrameworkTree, error) {
	raw, err := c.Eval(ctx, reactFiberWalkJS, cdp.EvalOpts{})
	if err != nil {
		return nil, err
	}
	return decodeFrameworkTree(raw)
}
