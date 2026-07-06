package cdp

import (
	"encoding/json"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture"
)

// RegisterNetworkHandlers registers CDP Network domain event handlers.
func (c *Client) RegisterNetworkHandlers() {
	pending := make(map[string]string) // requestId -> url

	c.OnEvent("Network.requestWillBeSent", func(params json.RawMessage) {
		var data struct {
			RequestID string `json:"requestId"`
			Request   struct {
				Method  string            `json:"method"`
				URL     string            `json:"url"`
				Headers map[string]string `json:"headers"`
			} `json:"request"`
			PostData string `json:"postData"`
		}
		if err := json.Unmarshal(params, &data); err != nil {
			return
		}

		pending[data.RequestID] = data.Request.URL

		evt, err := capture.NewEvent(c.seqFn(), time.Now(), capture.EventNetworkRequest, capture.SourceCDP,
			capture.NetworkRequestData{
				Method:  data.Request.Method,
				URL:     data.Request.URL,
				Headers: data.Request.Headers,
				Body:    data.PostData,
			})
		if err != nil {
			return
		}
		c.Emit(evt)
	})

	c.OnEvent("Network.responseReceived", func(params json.RawMessage) {
		var data struct {
			RequestID string `json:"requestId"`
			Response  struct {
				Status  int               `json:"status"`
				URL     string            `json:"url"`
				Headers map[string]string `json:"headers"`
			} `json:"response"`
		}
		if err := json.Unmarshal(params, &data); err != nil {
			return
		}

		delete(pending, data.RequestID)

		evt, err := capture.NewEvent(c.seqFn(), time.Now(), capture.EventNetworkResponse, capture.SourceCDP,
			capture.NetworkResponseData{
				Status:  data.Response.Status,
				URL:     data.Response.URL,
				Headers: data.Response.Headers,
			})
		if err != nil {
			return
		}
		c.Emit(evt)
	})
}
