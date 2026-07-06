/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// angularWalkJS is the Angular 9+ devtools walk via the global ng.getComponent
// helper. Returns null when ng helper is absent (production prod-mode build).
const angularWalkJS = `(function(){
  try {
    if (typeof ng === "undefined" || !ng || typeof ng.getComponent !== "function") return null;
    var nodeCount = 0;
    var MAX_NODES = 100000;
    var MAX_DEPTH = 1000;
    var seen = new WeakSet();
    function walk(el, depth) {
      if (!el || depth > MAX_DEPTH || nodeCount >= MAX_NODES) return null;
      nodeCount++;
      var name = "";
      try {
        var comp = ng.getComponent(el);
        if (comp && comp.constructor && comp.constructor.name) name = comp.constructor.name;
      } catch(e){}
      if (!name) name = (el.tagName || "Element").toLowerCase();
      var node = { name: name, children: [] };
      var children = el.children || [];
      for (var i = 0; i < children.length; i++) {
        if (seen.has(children[i])) continue;
        seen.add(children[i]);
        var c = walk(children[i], depth + 1);
        if (c) node.children.push(c);
      }
      return node;
    }
    var hosts = document.querySelectorAll("[ng-version]");
    if (!hosts.length) hosts = [document.body];
    var roots = [];
    for (var i = 0; i < hosts.length; i++) {
      var r = walk(hosts[i], 0);
      if (r) roots.push(r);
    }
    return roots.length ? roots : null;
  } catch(e) { return null; }
})()`

func extractAngularTree(ctx context.Context, c *cdp.Client) (*FrameworkTree, error) {
	raw, err := c.Eval(ctx, angularWalkJS, cdp.EvalOpts{})
	if err != nil {
		return nil, err
	}
	return decodeFrameworkTree(raw)
}
