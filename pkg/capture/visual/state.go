/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

// StateEvent describes a single state change observed on the target page.
type StateEvent struct {
	Type  string // "route" | "modal_open" | "modal_close"
	Slug  string
	Label string
}

// modalObserverJS is the injected MutationObserver that watches for [role=dialog]
// or [aria-modal=true] subtree insertions/removals and posts state events back
// to the orchestrator via the Runtime-bound __unravel_state_event(...) callback.
//
// Verbatim from RESEARCH §"Pattern 3: Modal/dialog mutation observer".
const modalObserverJS = `(function(){
  if (window.__unravel_state_observer_installed) return;
  window.__unravel_state_observer_installed = true;
  function dispatch(payload){
    try { if (typeof __unravel_state_event === "function") __unravel_state_event(JSON.stringify(payload)); } catch(e){}
  }
  function isModal(el){
    if (!el || el.nodeType !== 1) return false;
    if (el.matches && (el.matches('[role="dialog"]') || el.matches('[aria-modal="true"]'))) return true;
    return false;
  }
  function labelOf(el){
    if (!el) return "";
    if (el.getAttribute) {
      var l = el.getAttribute("aria-label") || el.getAttribute("data-modal") || el.getAttribute("id") || "";
      return l;
    }
    return "";
  }
  var mo = new MutationObserver(function(records){
    for (var i = 0; i < records.length; i++) {
      var rec = records[i];
      for (var j = 0; j < rec.addedNodes.length; j++) {
        if (isModal(rec.addedNodes[j])) dispatch({type:"modal_open", label: labelOf(rec.addedNodes[j])});
      }
      for (var k = 0; k < rec.removedNodes.length; k++) {
        if (isModal(rec.removedNodes[k])) dispatch({type:"modal_close", label: labelOf(rec.removedNodes[k])});
      }
    }
  });
  if (document.body) mo.observe(document.body, {childList:true, subtree:true});
  else document.addEventListener("DOMContentLoaded", function(){ mo.observe(document.body, {childList:true, subtree:true}); });
})()`

// RegisterStateDetectors wires Page.frameNavigated + Runtime.addBinding for
// the injected MutationObserver, invoking onState on every detected change.
// The orchestrator drives capture passes off these events.
func RegisterStateDetectors(ctx context.Context, c *cdp.Client, onState func(StateEvent)) error {
	c.OnEvent("Page.frameNavigated", func(params json.RawMessage) {
		defer func() { _ = recover() }()
		var d struct {
			Frame struct {
				URL string `json:"url"`
			} `json:"frame"`
		}
		if err := json.Unmarshal(params, &d); err != nil {
			return
		}
		onState(StateEvent{Type: "route", Slug: routeSlug(d.Frame.URL)})
	})
	if _, err := c.SendAndWait(ctx, "Runtime.addBinding", map[string]any{"name": "__unravel_state_event"}); err != nil {
		return fmt.Errorf("add binding: %w", err)
	}
	c.OnEvent("Runtime.bindingCalled", func(params json.RawMessage) {
		defer func() { _ = recover() }()
		var d struct {
			Name    string `json:"name"`
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(params, &d); err != nil {
			return
		}
		if d.Name != "__unravel_state_event" {
			return
		}
		var p struct {
			Type  string `json:"type"`
			Label string `json:"label"`
		}
		if err := json.Unmarshal([]byte(d.Payload), &p); err != nil {
			return
		}
		onState(StateEvent{Type: p.Type, Slug: modalSlug(p.Type, p.Label), Label: p.Label})
	})
	if _, err := c.SendAndWait(ctx, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": modalObserverJS}); err != nil {
		return fmt.Errorf("install modal observer: %w", err)
	}
	return nil
}

var nonURLChar = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

// routeSlug derives a path-component slug from a URL.
func routeSlug(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.Index(u, "/"); i >= 0 {
		u = u[i:]
	} else {
		u = ""
	}
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	s := strings.Trim(u, "/")
	s = nonURLChar.ReplaceAllString(s, "-")
	if s == "" {
		return "root"
	}
	return s
}

// modalSlug derives a slug for a modal open/close event.
func modalSlug(typ, label string) string {
	if typ == "modal_close" {
		return ""
	}
	if label == "" {
		label = "anon"
	}
	return "modal-" + nonURLChar.ReplaceAllString(strings.ToLower(label), "-")
}
