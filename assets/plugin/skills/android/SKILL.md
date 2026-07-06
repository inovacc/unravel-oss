---
name: android
description: Android APK security analysis
---

For APK files, use these tools in order:
1. `unravel_android_info` — package metadata and structure
2. `unravel_android_manifest` — permissions, components, security flags
3. `unravel_android_secrets` — API keys, tokens, credentials
4. `unravel_android_network` — endpoints, cert pinning, network config
5. `unravel_android_obfuscation` — ProGuard/R8/DexGuard detection
6. `unravel_android_telemetry` — analytics/ad/attribution SDKs

Or use `unravel_dissect` to run all of these automatically.
