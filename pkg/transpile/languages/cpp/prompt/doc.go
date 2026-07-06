// Package prompt constructs the C/C++ system and user prompts for Claude API calls.
// It provides a base C/C++ to Go conversion prompt enriched with library-specific
// rules fetched from GitHub and verified via HMAC-SHA512 signatures. Rules cover
// C++ libraries (STL, Boost, Qt, etc.), C standard library, POSIX, and Win32 APIs.
// Python prompt construction is handled by the Python language plugin.
package prompt
