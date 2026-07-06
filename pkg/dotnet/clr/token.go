/*
Copyright (c) 2026 Security Research
*/
package clr

import "github.com/inovacc/unravel-oss/pkg/dotnet/clr/clrtok"

// Token is the public clr alias for the canonical metadata token type, which
// lives in the leaf package clrtok (ECMA-335 II.22). It is a type *alias*, so
// clr.Token and clrtok.Token are the identical type: values flow between the
// clr API and the metadata/sig/il layers (which use clrtok.Token) with no
// conversion. The high byte is the table id; the low 24 bits are the 1-based
// row id (RID); a zero token is the nil token.
type Token = clrtok.Token
