/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/leveldb"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type leveldbParseInput struct {
	Path string `json:"path" jsonschema:"Path to LevelDB directory to parse"`
}

func registerLeveldbTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_leveldb_parse",
		Description: "Parse a LevelDB database directory, extracting entries from .log (WAL) and .ldb/.sst files",
	}, handleLeveldbParse)
}

func handleLeveldbParse(_ context.Context, _ *mcp.CallToolRequest, input leveldbParseInput) (*mcp.CallToolResult, any, error) {
	result, err := leveldb.ParseDirectory(input.Path)
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
