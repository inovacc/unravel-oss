/*
Copyright (c) 2026 Security Research

Package manifest provides a pure-Go decoder for Android binary XML
(AndroidManifest.xml) found inside APK archives.

The decoder parses the compiled AXML format used by aapt/aapt2, extracting
package metadata, permissions, components (activities, services, receivers,
providers), intent filters, and security-relevant flags.

Entry points:
  - ParseAPK:  opens an APK ZIP, locates AndroidManifest.xml, and decodes it
  - ParseAXML: decodes a raw binary XML byte slice
*/
package manifest
