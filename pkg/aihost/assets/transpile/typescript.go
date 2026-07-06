/*
Copyright (c) 2026 Security Research
*/
package transpile

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "skills/transpile/rules/typescript/express.md",
			Body: `# express → Go (net/http + chi)

- ` + "`" + `express()` + "`" + ` app → ` + "`" + `chi.NewRouter()` + "`" + ` (or ` + "`" + `http.ServeMux` + "`" + `).
- ` + "`" + `app.get(path, handler)` + "`" + ` → ` + "`" + `r.Get(path, handlerFunc)` + "`" + `; handler signature ` + "`" + `func(w http.ResponseWriter, req *http.Request)` + "`" + `.
- ` + "`" + `req.params.id` + "`" + ` → ` + "`" + `chi.URLParam(req, "id")` + "`" + `; ` + "`" + `req.query.x` + "`" + ` → ` + "`" + `req.URL.Query().Get("x")` + "`" + `.
- ` + "`" + `req.body` + "`" + ` (json) → ` + "`" + `json.NewDecoder(req.Body).Decode(&v)` + "`" + `.
- ` + "`" + `res.json(obj)` + "`" + ` → set ` + "`" + `Content-Type: application/json` + "`" + ` then ` + "`" + `json.NewEncoder(w).Encode(obj)` + "`" + `.
- ` + "`" + `res.status(code).send(...)` + "`" + ` → ` + "`" + `w.WriteHeader(code)` + "`" + ` then write body.
- Middleware ` + "`" + `(req, res, next) => {}` + "`" + ` → ` + "`" + `func(next http.Handler) http.Handler` + "`" + ` wrapper.
- ` + "`" + `app.listen(port)` + "`" + ` → ` + "`" + `http.ListenAndServe(addr, r)` + "`" + `.
- Error-handling middleware → centralized error helper returning ` + "`" + `error` + "`" + `, written to the response by the caller.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/typescript/node.md",
			Body: `# Node.js built-ins → Go standard library

- ` + "`" + `fs` + "`" + ` / ` + "`" + `fs/promises` + "`" + ` → ` + "`" + `os` + "`" + `, ` + "`" + `io` + "`" + `, ` + "`" + `os.ReadFile` + "`" + `, ` + "`" + `os.WriteFile` + "`" + `.
- ` + "`" + `path` + "`" + ` → ` + "`" + `path/filepath` + "`" + `.
- ` + "`" + `process.env.X` + "`" + ` → ` + "`" + `os.Getenv("X")` + "`" + `; ` + "`" + `process.argv` + "`" + ` → ` + "`" + `os.Args` + "`" + `; ` + "`" + `process.exit(n)` + "`" + ` → ` + "`" + `os.Exit(n)` + "`" + `.
- ` + "`" + `Buffer` + "`" + ` → ` + "`" + `[]byte` + "`" + `.
- ` + "`" + `EventEmitter` + "`" + ` → channels + goroutines, or a callback registry struct.
- ` + "`" + `http` + "`" + ` / ` + "`" + `https` + "`" + ` server → ` + "`" + `net/http` + "`" + `.
- ` + "`" + `crypto` + "`" + ` → ` + "`" + `crypto/*` + "`" + ` (sha256, hmac, rand).
- ` + "`" + `child_process` + "`" + ` → ` + "`" + `os/exec` + "`" + `.
- ` + "`" + `stream` + "`" + ` → ` + "`" + `io.Reader` + "`" + ` / ` + "`" + `io.Writer` + "`" + `.
- ` + "`" + `setTimeout` + "`" + ` / ` + "`" + `setInterval` + "`" + ` → ` + "`" + `time.AfterFunc` + "`" + ` / ` + "`" + `time.Ticker` + "`" + `.
- ` + "`" + `console.log` + "`" + ` → ` + "`" + `fmt.Println` + "`" + ` or ` + "`" + `log/slog` + "`" + `.
`,
		},
		aihost.Asset{
			Path: "skills/transpile/rules/typescript/zod.md",
			Body: `# zod → Go validation

- A ` + "`" + `z.object({...})` + "`" + ` schema → a Go struct with field types.
- ` + "`" + `z.string()` + "`" + `, ` + "`" + `z.number()` + "`" + `, ` + "`" + `z.boolean()` + "`" + ` → ` + "`" + `string` + "`" + `, ` + "`" + `float64` + "`" + `/` + "`" + `int` + "`" + `, ` + "`" + `bool` + "`" + `.
- ` + "`" + `.optional()` + "`" + ` → pointer field ` + "`" + `*T` + "`" + ` + ` + "`" + `validate:"omitempty"` + "`" + `.
- ` + "`" + `.min(n)` + "`" + `, ` + "`" + `.max(n)` + "`" + `, ` + "`" + `.email()` + "`" + `, ` + "`" + `.url()` + "`" + ` → ` + "`" + `go-playground/validator` + "`" + ` struct tags (` + "`" + `validate:"min=n"` + "`" + `, ` + "`" + `validate:"email"` + "`" + `).
- ` + "`" + `z.enum([...])` + "`" + ` → typed string constants + a validity check.
- ` + "`" + `z.array(T)` + "`" + ` → ` + "`" + `[]T` + "`" + `.
- ` + "`" + `schema.parse(data)` + "`" + ` → ` + "`" + `json.Unmarshal` + "`" + ` into the struct then ` + "`" + `validator.New().Struct(v)` + "`" + `; parse failure → returned ` + "`" + `error` + "`" + `.
- ` + "`" + `z.infer<typeof schema>` + "`" + ` → the Go struct type itself.
`,
		},
	)
}
