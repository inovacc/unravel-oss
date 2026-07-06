# mcp-sample-cli

A minimal Go MCP server that demonstrates the `pkg/mcp` sampling library.

## What it proves

`echo_uppercase` is a single MCP tool. When called, it uses `pkg/mcp.Sample`
to send a prompt to the connected MCP host (Claude Code) via the standard
`sampling/createMessage` reverse-RPC. The host returns the uppercased text,
proving the library is importable and callable from any external Go project
without depending on any Anthropic SDK.

## Build

```bash
go build -tags=example ./examples/mcp-sample-cli/
```

The `//go:build example` tag keeps this out of default `go build ./...` runs.

## Wire into Claude Code

Add to `.mcp.json`:

```json
{
  "mcpServers": {
    "sample-demo": {
      "command": "./mcp-sample-cli",
      "args": []
    }
  }
}
```

Then in a Claude Code conversation call the tool:

```
/mcp sample-demo echo_uppercase {"text": "hello world"}
```

Expected result: `HELLO WORLD` (returned by Claude Code via sampling).

## Key wiring pattern

```go
srv.Run(ctx, &gomcp.StdioTransport{
    AfterConnect: func(ss *gomcp.ServerSession) error {
        pkgmcp.SetSession(ss, logger)  // wire once
        return nil
    },
})

// In any tool handler:
body, err := pkgmcp.Sample(ctx, prompt)
```
