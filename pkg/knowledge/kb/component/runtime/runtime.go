/*
Copyright (c) 2026 Security Research

Package runtime wires every classifier rule package via blank import.
Importing this package once at process start guarantees the registry is
fully populated. Mirrors pkg/knowledge/kb/identity/runtime.

Phase 31 ships the 10 positive bucket packages plus the negatives package.
Future waves (e.g., heuristic / llm classifiers) will register here as well.
*/
package runtime

import (
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/auth"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/communication"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/crypto"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/ipc"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/negatives"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/protocol"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/security"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/stealth"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/storage"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/telemetry"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/ui"
)
