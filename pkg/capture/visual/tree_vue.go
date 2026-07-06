/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// vue3WalkJS is the Vue 3 devtools-hook walk payload (RESEARCH §"Vue 3").
// Vue 2 is intentionally NOT implemented (RESEARCH §"Vue 2: defer until first
// real-app surfacing"); returns null when only a Vue 2 hook is detected.
const vue3WalkJS = `(function(){
  try {
    var hook = window.__VUE_DEVTOOLS_GLOBAL_HOOK__;
    if (!hook) return null;
    if (hook.Vue && hook.Vue.version && hook.Vue.version.charAt(0) === "2") return null;
    var apps = hook.apps || (hook._buffer && hook._buffer.length ? hook._buffer.map(function(e){ return e[1]; }) : []);
    if (!apps || !apps.length) return null;
    var nodeCount = 0;
    var MAX_NODES = 100000;
    var MAX_DEPTH = 1000;
    function walk(comp, depth) {
      if (!comp || depth > MAX_DEPTH || nodeCount >= MAX_NODES) return null;
      nodeCount++;
      var t = comp.type || {};
      var name = t.name || t.__name || comp.appContext && comp.appContext.app && "App" || "Anonymous";
      var node = { name: String(name), children: [] };
      var subTree = comp.subTree;
      var queue = [subTree];
      while (queue.length) {
        var v = queue.shift();
        if (!v) continue;
        if (v.component) {
          var c = walk(v.component, depth + 1);
          if (c) node.children.push(c);
        } else if (Array.isArray(v.children)) {
          for (var i = 0; i < v.children.length; i++) queue.push(v.children[i]);
        }
      }
      return node;
    }
    var roots = [];
    for (var i = 0; i < apps.length; i++) {
      try {
        var inst = apps[i]._instance || apps[i];
        var r = walk(inst, 0);
        if (r) roots.push(r);
      } catch(e){}
    }
    return roots;
  } catch(e) { return null; }
})()`

func extractVue3Tree(ctx context.Context, c *cdp.Client) (*FrameworkTree, error) {
	raw, err := c.Eval(ctx, vue3WalkJS, cdp.EvalOpts{})
	if err != nil {
		return nil, err
	}
	return decodeFrameworkTree(raw)
}
