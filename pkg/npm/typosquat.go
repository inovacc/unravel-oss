package npm

import (
	"strings"
	"unicode"
)

// TyposquatResult holds the analysis of a package name for typosquatting.
type TyposquatResult struct {
	Package      string       `json:"package"`
	IsLikelyTypo bool         `json:"is_likely_typo"`
	SimilarTo    []SimilarPkg `json:"similar_to,omitempty"`
	Techniques   []string     `json:"techniques,omitempty"`
}

// SimilarPkg describes a popular package that the input name is similar to.
type SimilarPkg struct {
	Name     string `json:"name"`
	Distance int    `json:"distance"`
	Method   string `json:"method"`
}

// Top popular npm packages used as comparison targets.
var popularPackages = []string{
	"express", "react", "lodash", "axios", "webpack", "typescript", "next",
	"vue", "angular", "moment", "chalk", "commander", "inquirer", "glob",
	"fs-extra", "debug", "dotenv", "uuid", "yargs", "semver", "minimist",
	"rimraf", "mkdirp", "async", "bluebird", "underscore", "request",
	"body-parser", "cors", "cookie-parser", "jsonwebtoken", "bcrypt",
	"mongoose", "sequelize", "pg", "mysql2", "redis", "socket.io",
	"eslint", "prettier", "jest", "mocha", "chai", "sinon", "nyc",
	"babel-core", "babel-loader", "webpack-cli", "webpack-dev-server",
	"react-dom", "react-router", "react-router-dom", "redux", "react-redux",
	"next-auth", "prisma", "zod", "ajv", "joi", "yup",
	"tailwindcss", "postcss", "autoprefixer", "sass", "less",
	"esbuild", "rollup", "vite", "turbo", "nx",
	"node-fetch", "got", "superagent", "cheerio", "puppeteer",
	"winston", "pino", "morgan", "bunyan",
	"dayjs", "date-fns", "luxon",
	"ramda", "rxjs", "immer",
	"nodemon", "concurrently", "cross-env", "dotenv-cli",
	"open", "ora", "execa", "nanoid", "cuid",
	"tar", "archiver", "adm-zip",
	"sharp", "jimp", "canvas",
	"nodemailer", "twilio", "stripe",
	"passport", "helmet", "express-rate-limit",
	"graphql", "apollo-server", "type-graphql",
	"electron", "tauri",
}

// CheckTyposquatting analyzes a package name against known popular packages.
func CheckTyposquatting(name string) *TyposquatResult {
	result := &TyposquatResult{
		Package: name,
	}

	techniqueSet := make(map[string]bool)

	// Check for non-ASCII (homoglyph) characters
	if hasNonASCII(name) {
		techniqueSet["homoglyph"] = true
		result.IsLikelyTypo = true
	}

	// Check against each popular package
	for _, popular := range popularPackages {
		if name == popular {
			// Exact match — not a typosquat
			return &TyposquatResult{Package: name}
		}

		// Strip scope from input for comparison: "@evil/react" -> "react"
		stripped := stripScope(name)

		// 1. Levenshtein distance
		dist := levenshtein(stripped, popular)
		if dist > 0 && dist <= 2 {
			result.SimilarTo = append(result.SimilarTo, SimilarPkg{
				Name:     popular,
				Distance: dist,
				Method:   "levenshtein",
			})
			if dist == 1 {
				techniqueSet["character-swap"] = true
			} else {
				techniqueSet["near-match"] = true
			}
		}

		// 2. Hyphen omission/addition
		if checkHyphenVariant(stripped, popular) {
			// Avoid duplicate if already caught by levenshtein
			if dist > 2 {
				result.SimilarTo = append(result.SimilarTo, SimilarPkg{
					Name:     popular,
					Distance: dist,
					Method:   "hyphen-omission",
				})
			}
			techniqueSet["missing-hyphen"] = true
		}

		// 3. Scope confusion: "@evil/react" vs "@types/react"
		if stripped != name && stripped == popular {
			result.SimilarTo = append(result.SimilarTo, SimilarPkg{
				Name:     popular,
				Distance: 0,
				Method:   "scope-confusion",
			})
			techniqueSet["scope-confusion"] = true
		}

		// 4. Prefix/suffix squatting: "express-helper" matching "express"
		if stripped != popular && len(stripped) > len(popular)+1 {
			if strings.HasPrefix(stripped, popular+"-") || strings.HasSuffix(stripped, "-"+popular) {
				result.SimilarTo = append(result.SimilarTo, SimilarPkg{
					Name:     popular,
					Distance: len(stripped) - len(popular),
					Method:   "prefix-suffix",
				})
				// Less suspicious but note it
			}
		}

		// 5. Character repetition: "expresss" vs "express"
		if checkRepetition(stripped, popular) && dist > 2 {
			result.SimilarTo = append(result.SimilarTo, SimilarPkg{
				Name:     popular,
				Distance: dist,
				Method:   "character-repetition",
			})
			techniqueSet["character-repetition"] = true
		}
	}

	// Determine if this is likely a typosquat
	for _, sim := range result.SimilarTo {
		switch sim.Method {
		case "levenshtein", "scope-confusion", "missing-hyphen", "character-repetition":
			result.IsLikelyTypo = true
		}
	}

	// Collect techniques
	for t := range techniqueSet {
		result.Techniques = append(result.Techniques, t)
	}

	return result
}

// levenshtein computes the Levenshtein edit distance between two strings.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	// Use two rows for space efficiency.
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			ins := prev[j] + 1
			del := curr[j-1] + 1
			sub := prev[j-1] + cost

			curr[j] = min3(ins, del, sub)
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// stripScope removes the npm scope prefix: "@scope/name" -> "name"
func stripScope(name string) string {
	if strings.HasPrefix(name, "@") {
		if _, after, ok := strings.Cut(name, "/"); ok {
			return after
		}
	}
	return name
}

// hasNonASCII checks if the string contains any non-ASCII characters (homoglyphs).
func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

// checkHyphenVariant checks if removing or adding hyphens makes two names match.
// e.g., "lodash" vs "lo-dash", "fs-extra" vs "fsextra"
func checkHyphenVariant(a, b string) bool {
	// Remove all hyphens and compare
	aNoH := strings.ReplaceAll(a, "-", "")
	bNoH := strings.ReplaceAll(b, "-", "")
	return aNoH == bNoH && a != b
}

// checkRepetition checks if one string is the other with a repeated character.
// e.g., "expresss" vs "express", "loddash" vs "lodash"
func checkRepetition(candidate, target string) bool {
	if len(candidate) != len(target)+1 {
		return false
	}

	skipped := false
	j := 0
	for i := 0; i < len(candidate) && j < len(target); i++ {
		if candidate[i] == target[j] {
			j++
			continue
		}
		// Allow skipping one character if it matches the previous
		if !skipped && i > 0 && candidate[i] == candidate[i-1] {
			skipped = true
			continue
		}
		return false
	}
	return j == len(target)
}
