package triage

import (
	"strings"
	"testing"
)

// pad appends filler bytes so a body clears DefaultMinBody without
// disturbing whole-body shape regexes (only used for cases that don't rely
// on an exact whole-body match).
func pad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat("/", n-len(s))
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name    string
		modName string
		body    string
		minBody int
		want    Class
	}{
		{
			name:    "SKIP-too-small",
			modName: "app_module_1",
			body:    "return 1;",
			minBody: 0, // use DefaultMinBody (256)
			want:    Skip,
		},
		{
			name:    "SKIP-vendored-name",
			modName: "react-dom-a1b2c3",
			body:    pad("function App(){return null}", 300),
			minBody: 0,
			want:    Skip,
		},
		{
			name:    "SKIP-vendored-body",
			modName: "teams_module_4821",
			body:    pad("// module path: node_modules/lodash/index.js\nfunction noop(){}", 300),
			minBody: 0,
			want:    Skip,
		},
		{
			name:    "SKIP-pure-reexport",
			modName: "teams_module_9931",
			body:    `"use strict";n.r(t),n.d(t,"a",function(){return o}),n.d(t,"b",function(){return p});`,
			minBody: 1,
			want:    Skip,
		},
		{
			name:    "STATIC_OK-icon-factory",
			modName: "IconArrowRight",
			body: `function IconArrowRight(props){return n.createElement("svg",` +
				`{viewBox:"0 0 24 24",width:props.size||24,height:props.size||24},` +
				`n.createElement("path",{d:"M12 2L2 7l10 5 10-5-10-5z"}))}`,
			minBody: 1,
			want:    StaticOK,
		},
		{
			name:    "STATIC_OK-lazy-binding",
			modName: "teams_module_1204",
			body: `"use strict";Object.defineProperty(exports,"__esModule",{value:!0});` +
				`Object.defineProperty(exports,"foo",{enumerable:!0,get:function(){return _foo.foo}});`,
			minBody: 1,
			want:    StaticOK,
		},
		{
			name:    "STATIC_OK-graphql-fragment",
			modName: "teams_module_5510",
			body:    pad(`{"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserFragment"}}`, 300),
			minBody: 0,
			want:    StaticOK,
		},
		{
			name:    "ENRICH-icon-marker-in-large-module",
			modName: "trouter_notification_renderer",
			body: pad(`function renderNotificationBanner(state, dispatch) {
  if (!state.pending.length) return null;
  const item = state.pending[0];
  const icon = n.createElement("svg", {viewBox: "0 0 24 24"}, n.createElement("path", {d: "M12 2L2 7z"}));
  const onDismiss = () => dispatch({type: "DISMISS_NOTIFICATION", id: item.id});
  const onAction = () => {
    trackEvent("notification_action", {id: item.id, kind: item.kind});
    dispatch({type: "RESOLVE_NOTIFICATION", id: item.id});
  };
  return n.createElement(
    "div",
    {className: "banner"},
    icon,
    n.createElement("button", {onClick: onAction}, item.label),
    n.createElement("button", {onClick: onDismiss}, "Dismiss")
  );
}`, maxStaticOKBodyBytes+200),
			minBody: 0,
			want:    Enrich,
		},
		{
			name:    "ENRICH-graphql-marker-in-large-module",
			modName: "trouter_user_profile_loader",
			body: pad(`function loadUserProfile(client, userId) {
  const query = {"kind":"FragmentDefinition","name":{"kind":"Name","value":"UserFragment"}};
  const cached = profileCache.get(userId);
  if (cached && !isStale(cached)) {
    return Promise.resolve(cached);
  }
  return client.execute(query, {userId}).then(result => {
    const normalized = normalizeUserProfile(result.data);
    profileCache.set(userId, normalized);
    emitProfileLoaded(userId, normalized);
    return normalized;
  }).catch(err => {
    logProfileLoadError(userId, err);
    throw err;
  });
}`, maxStaticOKBodyBytes+200),
			minBody: 0,
			want:    Enrich,
		},
		{
			name:    "ENRICH-default",
			modName: "trouter_ipc_dispatch",
			body: pad(`function dispatchIPCMessage(channel, payload) {
  if (!registeredHandlers.has(channel)) {
    logUnhandledChannel(channel);
    return;
  }
  const handler = registeredHandlers.get(channel);
  const result = handler(payload);
  return normalizeIPCResult(result);
}`, 300),
			minBody: 0,
			want:    Enrich,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.modName, []byte(tt.body), tt.minBody)
			if got != tt.want {
				t.Errorf("Classify(%q, len=%d, minBody=%d) = %v, want %v",
					tt.modName, len(tt.body), tt.minBody, got, tt.want)
			}
		})
	}
}

func TestClassify_MinBodyDefault(t *testing.T) {
	shortBody := []byte(strings.Repeat("a", DefaultMinBody-1))
	if got := Classify("mod", shortBody, 0); got != Skip {
		t.Errorf("body one byte under DefaultMinBody: got %v, want Skip", got)
	}

	longBody := []byte(strings.Repeat("a", DefaultMinBody))
	if got := Classify("mod", longBody, 0); got != Enrich {
		t.Errorf("body exactly DefaultMinBody: got %v, want Enrich", got)
	}
}

func TestClassify_VendoredPrecedesReexportAndStatic(t *testing.T) {
	// A vendored-named module whose body would otherwise match the
	// pure-reexport shape must still classify SKIP via the vendored path,
	// not fall through — precedence order shouldn't matter for the
	// resulting class here since both paths land on Skip, but this pins
	// the vendored-by-name short-circuit explicitly.
	body := `"use strict";n.r(t),n.d(t,"a",function(){return o});`
	got := Classify("lodash-9f8e7d", []byte(body), 1)
	if got != Skip {
		t.Errorf("Classify(vendored name + reexport body) = %v, want Skip", got)
	}
}
