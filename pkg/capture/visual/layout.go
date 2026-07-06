/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// Soft / hard caps for layout extraction (T-08-05; D-07).
//
//	JS-side soft cap (50,000 elements) is enforced inside the eval payload —
//	if the page has more elements, the script truncates and returns a marker
//	{truncated: true, total_elements: N, captured: 50000}.
//	Go-side hard cap (50 MiB) catches any payload that escapes the JS cap
//	(e.g., very large computed-style maps).
const (
	layoutByteHardCap = 50 * 1024 * 1024 // 50 MiB
	layoutByteWarn    = 10 * 1024 * 1024 // 10 MiB warn threshold
	layoutMaxElements = 50000            // JS-side soft cap
)

// LayoutSpec is the JSON shape written to layout.json.
type LayoutSpec struct {
	Entries       []LayoutEntry `json:"entries"`
	Truncated     bool          `json:"truncated"`
	TotalElements int           `json:"total_elements,omitempty"`
	Captured      int           `json:"captured,omitempty"`
}

// LayoutEntry is one element's bounds + computed style + DOM path.
type LayoutEntry struct {
	DOMPath       string            `json:"dom_path"`
	Bounds        Bounds            `json:"bounds"`
	ComputedStyle map[string]string `json:"computed_style"`
}

// computedStyleScript walks every element in document.body, captures bounds +
// getComputedStyle output + a derived DOM path, and stops at maxElements
// emitting a truncation marker. Verbatim style of RESEARCH §"Computed-style
// snapshot"; the marker entry is the LAST element of the returned array.
var computedStyleScript = `(function(maxElements){
  try {
    var STYLE_KEYS = ["display","position","z-index","background-color","color",
      "font-family","font-size","font-weight","border","margin","padding",
      "width","height","opacity","visibility","overflow","flex","grid-template-columns","grid-template-rows"];
    function pathOf(el){
      var parts = [];
      while (el && el.nodeType === 1 && parts.length < 32) {
        var seg = el.tagName.toLowerCase();
        if (el.id) { seg += "#" + el.id; parts.unshift(seg); break; }
        if (el.className && typeof el.className === "string") {
          var cls = el.className.trim().split(/\s+/).slice(0,2).join(".");
          if (cls) seg += "." + cls;
        }
        parts.unshift(seg);
        el = el.parentElement;
      }
      return parts.join(" > ");
    }
    var all = document.body ? document.body.querySelectorAll("*") : [];
    var total = all.length;
    var entries = [];
    var n = Math.min(total, maxElements);
    for (var i = 0; i < n; i++) {
      var el = all[i];
      try {
        var r = el.getBoundingClientRect();
        var cs = window.getComputedStyle(el);
        var style = {};
        for (var k = 0; k < STYLE_KEYS.length; k++) {
          var v = cs.getPropertyValue(STYLE_KEYS[k]);
          if (v) style[STYLE_KEYS[k]] = v;
        }
        entries.push({
          dom_path: pathOf(el),
          bounds: { x: r.left, y: r.top, w: r.width, h: r.height,
                    visible: !!(r.width && r.height && cs.visibility !== "hidden" && cs.display !== "none"),
                    z_index: cs.zIndex || "" },
          computed_style: style
        });
      } catch(e){}
    }
    if (total > maxElements) {
      entries.push({ truncated: true, total_elements: total, captured: maxElements });
    }
    return entries;
  } catch(e) { return []; }
})(` + fmt.Sprintf("%d", layoutMaxElements) + `)`

// ExtractLayout invokes the computed-style script and returns a LayoutSpec.
// Enforces the 50 MiB byte hard cap on the wire payload (D-07).
func ExtractLayout(ctx context.Context, c *cdp.Client) (out *LayoutSpec, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("layout extract panic: %v", r)
		}
	}()
	raw, err := c.Eval(ctx, computedStyleScript, cdp.EvalOpts{})
	if err != nil {
		return nil, fmt.Errorf("eval layout script: %w", err)
	}
	if len(raw) > layoutByteHardCap {
		return &LayoutSpec{Truncated: true, TotalElements: -1, Captured: -1},
			fmt.Errorf("layout.json exceeds 50 MiB hard cap (%d bytes)", len(raw))
	}
	return parseLayout(raw)
}

// parseLayout decodes the JS payload into a LayoutSpec, surfacing any
// truncation marker emitted by the script.
func parseLayout(raw json.RawMessage) (*LayoutSpec, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("decode layout array: %w", err)
	}
	spec := &LayoutSpec{}
	for _, item := range arr {
		// Detect truncation marker first (it has no dom_path field).
		var marker struct {
			Truncated     bool `json:"truncated"`
			TotalElements int  `json:"total_elements"`
			Captured      int  `json:"captured"`
		}
		if err := json.Unmarshal(item, &marker); err == nil && marker.Truncated {
			spec.Truncated = true
			spec.TotalElements = marker.TotalElements
			spec.Captured = marker.Captured
			continue
		}
		var entry LayoutEntry
		if err := json.Unmarshal(item, &entry); err != nil {
			continue
		}
		spec.Entries = append(spec.Entries, entry)
	}
	return spec, nil
}
