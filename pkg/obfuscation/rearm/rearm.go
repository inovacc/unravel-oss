/*
Copyright (c) 2026 Security Research
*/
package rearm

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var mechLine = regexp.MustCompile(`(?i)MECHANISM:\s*([^\|\n]+)\|\s*(\d{1,3})`)
var codeFence = regexp.MustCompile("(?s)```[a-zA-Z0-9]*\\n(.*?)```")

func buildPrompt(c Candidate) string {
	return fmt.Sprintf(`You are a reverse-engineering assistant. The following %s code is obfuscated/minified.
1) Identify the obfuscation mechanism/tool (e.g. terser, webpack, javascript-obfuscator, garble, ProGuard/R8, ConfuserEx).
2) Output deobfuscated, readable, functionally-equivalent source.
Respond EXACTLY as:
MECHANISM: <name>|<confidence 0-100>
then a single fenced code block with the reconstructed source.`, c.Lang)
}

// rearmOne performs one bounded AI classify+reconstruct pass. All failures are
// returned (never panics); the caller decides status.
func rearmOne(ctx context.Context, b Beautifier, c Candidate) (mech string, conf int, code string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("rearm panic: %v", r)
		}
	}()
	resp, e := b.Beautify(ctx, buildPrompt(c), c.Source)
	if e != nil {
		return "", 0, "", e
	}
	if m := mechLine.FindStringSubmatch(resp); m != nil {
		mech = strings.TrimSpace(m[1])
		conf, _ = strconv.Atoi(m[2])
		if conf > 100 {
			conf = 100
		}
	}
	if cm := codeFence.FindStringSubmatch(resp); cm != nil {
		code = strings.TrimSpace(cm[1])
	}
	if mech == "" && code == "" {
		return "", 0, "", fmt.Errorf("unparseable AI response")
	}
	return mech, conf, code, nil
}
