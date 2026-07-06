package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPromote(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "webpack source path comment",
			body: `var x = require("src/foo/bar.ts"); doStuff();`,
			want: "bar",
		},
		{
			name: "WAWeb log tag",
			body: `WALogger.LOG(["[WAWebMsgCollection] hello"]);`,
			want: "WAWebMsgCollection",
		},
		{
			name: "bare WAWeb identifier",
			body: `var m = WAWebFooBarBaz;`,
			want: "WAWebFooBarBaz",
		},
		{
			name: "TS_GLOBAL channel name",
			body: `TS.SOME_CHANNEL_NAME.handle();`,
			want: "SOME_CHANNEL_NAME",
		},
		{
			name: "no signal returns empty",
			body: `function() { return 42; }`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Promote(tt.body)
			if got != tt.want {
				t.Errorf("Promote() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSymbols(t *testing.T) {
	body := `
		fetch("https://api.example.com/v1/foo");
		bus.on("user:login", handler);
		db.createObjectStore("messages");
		localStorage.setItem("auth_token", "x");
		WALogger.LOG(["[CRYPTO_INIT] ok"]);
		require("WAWebSignalProtocol");
		fetch("/api/users/me");
	`
	out := Symbols(body)
	if out == "" {
		t.Fatal("Symbols returned empty for body with many signals")
	}
	var got map[string][]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("Symbols not valid JSON: %v", err)
	}

	wantKeys := []string{"urls", "events", "db_stores", "ls_keys", "log_tags", "wa_modules", "json_endpoints"}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in symbols output: %v", k, got)
		}
	}
}

func TestSymbolsEmptyWhenNoSignal(t *testing.T) {
	if got := Symbols(`var a = 1; var b = 2;`); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestModBodySlicesCorrectly(t *testing.T) {
	src := []byte("XXXXhello worldYYYY")
	m := Mod{Name: "n", Offset: 4, Size: 11}
	got := m.Body(src, 100)
	if got != "hello world" {
		t.Errorf("Body = %q, want %q", got, "hello world")
	}
	// max truncation
	got = m.Body(src, 5)
	if got != "hello" {
		t.Errorf("Body truncated = %q, want %q", got, "hello")
	}
}

func TestScanMeta(t *testing.T) {
	src := []byte(`__d("WAWebMsgCollection",function(){return 1;});` +
		`__d("WAWebChat",function(){return 2;});`)
	mods := ScanMeta(src)
	if len(mods) != 2 {
		t.Fatalf("expected 2 mods, got %d", len(mods))
	}
	if mods[0].Name != "WAWebMsgCollection" {
		t.Errorf("first mod name = %q", mods[0].Name)
	}
	if mods[1].Name != "WAWebChat" {
		t.Errorf("second mod name = %q", mods[1].Name)
	}
}

func TestScanMetaEmpty(t *testing.T) {
	if got := ScanMeta([]byte(`var a = 1;`)); got != nil {
		t.Errorf("expected no mods, got %d", len(got))
	}
}

func TestScanSingle(t *testing.T) {
	data := []byte(strings.Repeat("a", 200))
	mods := ScanSingle(data, "/root", "/root/sub/foo.js", 100)
	if len(mods) != 1 {
		t.Fatalf("expected 1 mod, got %d", len(mods))
	}
	if mods[0].Name != "foo" {
		t.Errorf("mod name = %q, want %q", mods[0].Name, "foo")
	}
	if mods[0].Size != 200 {
		t.Errorf("mod size = %d, want 200", mods[0].Size)
	}
}

func TestScanSingleBelowMin(t *testing.T) {
	if got := ScanSingle([]byte("tiny"), "/root", "/root/foo.js", 100); got != nil {
		t.Errorf("expected nil for under-min file")
	}
}

func TestPrefix(t *testing.T) {
	tests := []struct {
		name string
		mod  Mod
		want string
	}{
		{"non-WAWeb", Mod{Name: "foo"}, ""},
		{"WAWeb only", Mod{Name: "WAWeb"}, "WAWeb"},
		{"WAWebMsgCollection", Mod{Name: "WAWebMsgCollection"}, "WAWebMsg"},
		{"WAWebChat", Mod{Name: "WAWebChat"}, "WAWebChat"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mod.Prefix(); got != tt.want {
				t.Errorf("Prefix() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScanWebpackFunctionFactory(t *testing.T) {
	src := []byte(`{12345:function(e,t,n){return 1;},67890:function(){return 2;}}`)
	mods := ScanWebpack(src, "teams")
	if len(mods) < 2 {
		t.Fatalf("expected >=2 mods, got %d (%+v)", len(mods), mods)
	}
	want := map[string]bool{"teams_module_12345": true, "teams_module_67890": true}
	for _, m := range mods {
		if !want[m.Name] {
			t.Errorf("unexpected mod name %q", m.Name)
		}
	}
}

func TestScanWebpackArrowFactory(t *testing.T) {
	src := []byte(`{42:(e,t,n)=>{return 1;}}`)
	mods := ScanWebpack(src, "slack")
	if len(mods) == 0 {
		t.Fatal("expected at least 1 mod for arrow factory")
	}
	if mods[0].Name != "slack_module_42" {
		t.Errorf("name = %q", mods[0].Name)
	}
}

// TestPromoteWebpackExport asserts the new Tier-2 promotion paths added to
// recover real names for Teams/LinkedIn modules where the old WAWeb-shaped
// heuristics returned empty (defect 2).
func TestPromoteWebpackExport(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "webpack export define",
			body: `__webpack_require__.d(t,"MessageBus",function(){return r});`,
			want: "MessageBus",
		},
		{
			name: "minified webpack d-export object (LinkedIn 2024+ shape)",
			body: `(e,t,n)=>{"use strict";n.r(t),n.d(t,{ConversationsIterable:()=>Tt,Mailbox:()=>Jf});`,
			want: "ConversationsIterable",
		},
		{
			name: "MicrosoftTeams namespace",
			body: `var x = MicrosoftTeams.ChatService.send();`,
			want: "ChatService",
		},
		{
			name: "class declaration",
			body: `var foo=1;class TrouterClient{constructor(){}}`,
			want: "TrouterClient",
		},
		{
			name: "first named function",
			body: `(function(){var a=1;function VoyagerRouter(opts){return opts;}})();`,
			want: "VoyagerRouter",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Promote(tt.body); got != tt.want {
				t.Errorf("Promote() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestPromoteWAWebRegression makes sure the Tier-1 WhatsApp paths still win
// when both old and new signals appear — protects the 100% WhatsApp promotion
// rate from regressing after the defect 2 patch.
func TestPromoteWAWebRegression(t *testing.T) {
	body := `WALogger.LOG(["[WAWebSendMsgChatAction] start"]); class TrouterClient{};`
	if got := Promote(body); got != "WAWebSendMsgChatAction" {
		t.Errorf("Promote regression: got %q want WAWebSendMsgChatAction", got)
	}
}

// TestPromoteFromChunkMap covers the runtime chunk-id-to-name lookup helper.
func TestPromoteFromChunkMap(t *testing.T) {
	runtime := `__webpack_require__.u=function(e){return"chunks/"+{0:"vendor",17:"messages.chunk",42:"presence"}[e]+".js"}`
	if got := PromoteFromChunkMap(runtime, "17"); got != "messages.chunk" {
		t.Errorf("got %q, want messages.chunk", got)
	}
	if got := PromoteFromChunkMap(runtime, "42"); got != "presence" {
		t.Errorf("got %q, want presence", got)
	}
	if got := PromoteFromChunkMap(runtime, "999"); got != "" {
		t.Errorf("expected empty for missing id, got %q", got)
	}
}

// TestSymbolsDensity asserts the upgraded Symbols extractor (defect 3) pulls
// substantially more symbols out of a realistic-shape JS body than the old
// 7-bucket version. Uses a synthetic ~1KB module with mixed signals.
func TestSymbolsDensity(t *testing.T) {
	body := `
		"use strict";
		const TARGET_URL = "/api/v1/messages";
		const RETRY_LIMIT = 5;
		function sendMessage(chatId, body){ return fetch(TARGET_URL, {method:"POST"}); }
		function receiveMessage(payload){ bus.emit("msg:received", payload); }
		function deriveKey(secret){ return crypto.subtle.deriveKey(secret); }
		class ChatStore {
		    init(){ this.db.createObjectStore("chats"); }
		    save(item){ localStorage.setItem("last_chat", item.id); }
		    load(){ return this.db.get("chats"); }
		}
		exports.sendMessage = sendMessage;
		exports.receiveMessage = receiveMessage;
		exports.ChatStore = ChatStore;
	`
	out := Symbols(body)
	if out == "" {
		t.Fatal("Symbols returned empty for rich body")
	}
	var got map[string][]string
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	total := 0
	for _, v := range got {
		total += len(v)
	}
	if total < 10 {
		t.Errorf("expected >10 total symbols across buckets, got %d (%+v)", total, got)
	}
	for _, key := range []string{"functions", "classes", "exports"} {
		if len(got[key]) == 0 {
			t.Errorf("missing or empty bucket %q in %+v", key, got)
		}
	}
}
