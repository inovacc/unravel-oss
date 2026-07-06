package generated

import "github.com/antlr4-go/antlr/v4"

// JavaParserBase is the Go port of JavaParserBase.java.
// It provides predicate methods used by the grammar actions.
type JavaParserBase struct {
	*antlr.BaseParser
}

// DoLastRecordComponent checks that a varargs (ELLIPSIS) parameter
// only appears as the last component in a record component list.
func (p *JavaParserBase) DoLastRecordComponent() bool {
	ctx := p.GetParserRuleContext()

	rcl, ok := ctx.(*RecordComponentListContext)
	if !ok {
		return true
	}

	rcs := rcl.AllRecordComponent()
	if len(rcs) == 0 {
		return true
	}

	count := len(rcs)
	for c := range count {
		rc, ok := rcs[c].(*RecordComponentContext)
		if !ok {
			continue
		}

		if rc.ELLIPSIS() != nil && c+1 < count {
			return false
		}
	}

	return true
}

// IsNotIdentifierAssign returns true when the next two tokens do NOT
// form an "identifier = ..." pattern. This is used in annotation parsing
// to distinguish positional annotation values from named ones.
func (p *JavaParserBase) IsNotIdentifierAssign() bool {
	la := p.GetTokenStream().LT(1).GetTokenType()

	switch la {
	case JavaParserIDENTIFIER,
		JavaParserMODULE,
		JavaParserOPEN,
		JavaParserREQUIRES,
		JavaParserEXPORTS,
		JavaParserOPENS,
		JavaParserTO,
		JavaParserUSES,
		JavaParserPROVIDES,
		JavaParserWHEN,
		JavaParserWITH,
		JavaParserTRANSITIVE,
		JavaParserYIELD,
		JavaParserSEALED,
		JavaParserPERMITS,
		JavaParserRECORD,
		JavaParserVAR:
		// Could be identifier — check if next is '='
	default:
		return true
	}

	la2 := p.GetTokenStream().LT(2).GetTokenType()

	return la2 != JavaParserASSIGN
}
