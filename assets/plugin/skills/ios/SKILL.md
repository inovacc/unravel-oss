---
name: ios
description: iOS IPA security analysis
---

For IPA files:
1. `unravel_ios_info` — bundle ID, version, permissions, Mach-O metadata, code signing
2. `unravel_ios_extract` — extract IPA contents

The info tool automatically parses Info.plist, analyzes the Mach-O binary (CPU type, libraries, encryption, bitcode), and verifies code signing (entitlements, provisioning profile).
