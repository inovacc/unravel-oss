/*
Copyright (c) 2026 Security Research
*/
package ipc

// HelloRequest is the first message a client sends after dial.
type HelloRequest struct {
	Token         string `json:"token"`
	ClientVersion string `json:"client_version"`
	OS            string `json:"os"`
	PID           int    `json:"pid"`
}

// HelloResponse is the supervisor's reply.
type HelloResponse struct {
	ServerVersion   string `json:"server_version"`
	ServerUID       string `json:"server_uid"`
	ProtocolVersion string `json:"protocol_version"` // "1"
}
