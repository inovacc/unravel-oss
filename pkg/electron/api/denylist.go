/*
Copyright (c) 2026 Security Research
*/
package api

import "strings"

// denyHosts lists hosts whose appearance in JS source indicates a comment or
// spec reference, not a real runtime endpoint. Derived from observed Discord
// ASAR noise (BUG-07).
var denyHosts = []string{
	// Standards bodies / specs
	"w3.org", "www.w3.org", "w3c.github.io",
	"spec.whatwg.org", "fetch.spec.whatwg.org", "html.spec.whatwg.org", "whatwg.org",
	"tools.ietf.org", "datatracker.ietf.org",
	"iana.org", "www.iana.org",
	"json-schema.org",
	"semver.org",
	"opensource.org",
	"apache.org", "www.apache.org",
	"nist.gov", "csrc.nist.gov",

	// Issue trackers / source hosts (comment refs)
	"crbug.com", "bugs.chromium.org", "code.google.com",
	"dawn.googlesource.com", "googlesource.com",
	"gpuweb.github.io",
	"github.com", "raw.githubusercontent.com", "githubusercontent.com",
	"hackerone.com",
	"isecpartners.com",
	"json.com", "www.json.com",
	"amazonwebservices.com",
	"example.com", "www.example.com", "example.org", "www.example.org",

	// Vendor docs
	"nodejs.org", "nodejs.dev",
	"developer.mozilla.org", "mozilla.github.io",
	"developer.chrome.com",
	"electronjs.org",
	"reactjs.org", "react.dev",
	"learn.microsoft.com", "msdn.microsoft.com", "docs.microsoft.com",
	"docs.aws.amazon.com", "aws.amazon.com",
	"cloud.google.com",
	"tencentcloud.com", "www.tencentcloud.com",
	"developers.cloudflare.com",
	"docs.netlify.com", "netlify.com",
	"fly.io", "vercel.com",
	"devcenter.heroku.com", "heroku.com",
	"docs.python.org", "python.org",
	"caniuse.com",
	"web.dev",
	"docs.sentry.io", "develop.sentry.dev", "spotlightjs.com",

	// Q&A / blogs / personal sites commonly cited in JSDoc
	"stackoverflow.com",
	"dev.to",
	"twitter.com", "dev.twitter.com",
	"mathiasbynens.be", "sindresorhus.com", "feross.org",
	"safaribooksonline.com", "jmrware.com", "hertzen.com",
	"blueimp.net", "pajhome.org.uk", "movable-type.co.uk",
	"tartarus.org", "mths.be", "tweetnacl.cr.yp.to",
	"isc.org", "lynx.isc.org",
	"localforage.github.io",
	"en.wikipedia.org", "wikipedia.org",
}

// junkMidLabels are common English words that, when appearing as a middle DNS
// label, indicate a sentence-as-host placeholder (e.g. "dogs.are.great").
var junkMidLabels = map[string]bool{
	"are": true, "is": true, "the": true, "a": true, "an": true,
	"will": true, "be": true, "to": true, "of": true,
}

// isJunkHost reports whether host has obvious junk shape: TLD too short, or
// contains a placeholder middle label.
func isJunkHost(host string) bool {
	labels := strings.Split(strings.ToLower(host), ".")
	if len(labels) < 2 {
		return true
	}
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return true
	}
	for i := 1; i < len(labels)-1; i++ {
		if junkMidLabels[labels[i]] {
			return true
		}
	}
	return false
}

// denyHost reports whether host is on the spec/comment denylist.
// Match is case-insensitive, exact host or subdomain.
func denyHost(host string) bool {
	h := strings.ToLower(host)
	for _, d := range denyHosts {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}
