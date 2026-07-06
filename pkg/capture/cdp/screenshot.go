/*
Copyright (c) 2026 Security Research
*/
package cdp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// ScreenshotOpts configures Page.captureScreenshot.
type ScreenshotOpts struct {
	Format      string // "png" (default) | "jpeg" | "webp"
	Quality     int    // 0-100 (jpeg/webp only)
	FromSurface bool   // capture from surface (default true)
}

// CaptureScreenshot calls Page.captureScreenshot and returns the decoded image bytes.
func (c *Client) CaptureScreenshot(ctx context.Context, opts ScreenshotOpts) ([]byte, error) {
	if opts.Format == "" {
		opts.Format = "png"
	}
	params := map[string]any{
		"format":      opts.Format,
		"fromSurface": opts.FromSurface || true,
	}
	if opts.Quality > 0 {
		params["quality"] = opts.Quality
	}
	raw, err := c.SendAndWait(ctx, "Page.captureScreenshot", params)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode Page.captureScreenshot: %w", err)
	}
	out, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, fmt.Errorf("base64 decode screenshot: %w", err)
	}
	return out, nil
}
