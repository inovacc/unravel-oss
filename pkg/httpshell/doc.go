/*
Copyright (c) 2026 Security Research
*/

// Package httpshell provides a secure HTTP-based remote command execution shell.
//
// It includes an HTTPS server with IP whitelisting, auth ID verification, and
// command filtering, plus a client with interactive REPL support. TLS certificates
// are auto-generated if not present.
//
// Entry points:
//   - NewClient: create a client connected to a remote server
//   - Server.Start: start the HTTPS server on a given port
//   - GenerateSelfSignedCert: generate TLS certificate and key
//   - GenerateAuthID: create a random authentication identifier
package httpshell
