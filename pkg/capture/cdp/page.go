package cdp

import (
	"encoding/json"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// RegisterPageHandlers registers CDP Page domain event handlers.
func (c *Client) RegisterPageHandlers() {
	c.OnEvent("Page.frameNavigated", func(params json.RawMessage) {
		var data struct {
			Frame struct {
				URL string `json:"url"`
			} `json:"frame"`
		}
		if err := json.Unmarshal(params, &data); err != nil {
			return
		}

		evt, err := capture.NewEvent(c.seqFn(), time.Now(), capture.EventWindowState, capture.SourceCDP,
			capture.WindowStateData{
				Property: "navigation",
				Value:    data.Frame.URL,
			})
		if err != nil {
			return
		}
		c.Emit(evt)
	})
}
