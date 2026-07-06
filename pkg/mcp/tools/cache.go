/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"

	"github.com/inovacc/unravel-oss/pkg/cache"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type cacheParseInput struct {
	Path string `json:"path" jsonschema:"Path to cache directory (e.g. Cache/Cache_Data)"`
}

func registerCacheTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "unravel_cache_parse",
		Description: "Parse Chromium HTTP cache (Simple Cache or Block File format) extracting URLs, headers, and response bodies",
	}, handleCacheParse)
}

func handleCacheParse(_ context.Context, _ *mcp.CallToolRequest, input cacheParseInput) (*mcp.CallToolResult, any, error) {
	result, err := cache.Parse(input.Path, "")
	if err != nil {
		return errorResult(err), nil, nil
	}

	return jsonResult(result), nil, nil
}
