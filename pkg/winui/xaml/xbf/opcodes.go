/*
Copyright (c) 2026 Security Research
*/

package xbf

// Opcode is a single XBF v2.1 node-stream opcode. Values ported from
// XbfAnalyzer's XbfNodeType.cs (misenhower/XbfAnalyzer, archived).
type Opcode byte

// XBF v2.1 opcode set. Every constant declared here MUST appear in
// opcodeNames; any byte read from the stream that is NOT in opcodeNames is
// routed to the placeholder path.
const (
	OpEndOfStream                 Opcode = 0x01 // XbfNodeType.cs: EndOfStream
	OpLineInfo                    Opcode = 0x02 // XbfNodeType.cs: LineInfo
	OpLineInfoAbsolute            Opcode = 0x03 // XbfNodeType.cs: LineInfoAbsolute
	OpNamespace                   Opcode = 0x04 // XbfNodeType.cs: Namespace
	OpPushScope                   Opcode = 0x05 // XbfNodeType.cs: PushScope
	OpPopScope                    Opcode = 0x06 // XbfNodeType.cs: PopScope
	OpStartObject                 Opcode = 0x07 // XbfNodeType.cs: StartObject
	OpStartObjectFromMember       Opcode = 0x08 // XbfNodeType.cs: StartObjectFromMember
	OpEndObject                   Opcode = 0x09 // XbfNodeType.cs: EndObject
	OpStartMember                 Opcode = 0x0A // XbfNodeType.cs: StartMember
	OpStartMemberFromType         Opcode = 0x0B // XbfNodeType.cs: StartMemberFromType
	OpEndMember                   Opcode = 0x0C // XbfNodeType.cs: EndMember
	OpAddDirective                Opcode = 0x0D // XbfNodeType.cs: AddDirective
	OpAddText                     Opcode = 0x0E // XbfNodeType.cs: AddText
	OpStartProperty               Opcode = 0x0F // XbfNodeType.cs: StartProperty
	OpEndProperty                 Opcode = 0x10 // XbfNodeType.cs: EndProperty
	OpAddValue                    Opcode = 0x11 // XbfNodeType.cs: AddValue
	OpSetValue                    Opcode = 0x12 // XbfNodeType.cs: SetValue
	OpSetConnectionId             Opcode = 0x13 // XbfNodeType.cs: SetConnectionId
	OpSetName                     Opcode = 0x14 // XbfNodeType.cs: SetName
	OpGetResourcePropertyBag      Opcode = 0x15 // XbfNodeType.cs: GetResourcePropertyBag
	OpProvideValue                Opcode = 0x16 // XbfNodeType.cs: ProvideValue
	OpAddNamespace                Opcode = 0x17 // XbfNodeType.cs: AddNamespace (alias on some builds)
	OpAddDirectiveProperty        Opcode = 0x18 // XbfNodeType.cs: AddDirectiveProperty
	OpStartConditionalScope       Opcode = 0x19 // XbfNodeType.cs: StartConditionalScope
	OpEndConditionalScope         Opcode = 0x1A // XbfNodeType.cs: EndConditionalScope
	OpStartObjectWithName         Opcode = 0x1B // XbfNodeType.cs: StartObjectWithName
	OpEndObjectWithName           Opcode = 0x1C // XbfNodeType.cs: EndObjectWithName
	OpDeferredElement             Opcode = 0x1D // XbfNodeType.cs: DeferredElement
	OpStaticResource              Opcode = 0x1E // XbfNodeType.cs: StaticResource
	OpThemeResource               Opcode = 0x1F // XbfNodeType.cs: ThemeResource
	OpCustomBindingExpression     Opcode = 0x20 // XbfNodeType.cs: CustomBindingExpression
	OpTemplateBinding             Opcode = 0x21 // XbfNodeType.cs: TemplateBinding
	OpStreamOffsetMarker          Opcode = 0x22 // XbfNodeType.cs: StreamOffsetMarker
	OpEndOfAttributes             Opcode = 0x23 // XbfNodeType.cs: EndOfAttributes
	OpDeferredResourceDictionary  Opcode = 0x24 // XbfNodeType.cs: DeferredResourceDictionary
	OpResourceDictionaryReference Opcode = 0x25 // XbfNodeType.cs: ResourceDictionaryReference
	OpXNameReference              Opcode = 0x26 // XbfNodeType.cs: XNameReference
	OpXNameDirective              Opcode = 0x27 // XbfNodeType.cs: XNameDirective
	OpStaticResourceReference     Opcode = 0x28 // XbfNodeType.cs: StaticResourceReference
	OpThemeResourceReference      Opcode = 0x29 // XbfNodeType.cs: ThemeResourceReference
	OpResourceDictionaryEnd       Opcode = 0x2A // XbfNodeType.cs: ResourceDictionaryEnd
	OpExtensionPoint              Opcode = 0x2B // XbfNodeType.cs: ExtensionPoint
	OpUnknownReserved2C           Opcode = 0x2C // XbfNodeType.cs: reserved; render placeholder if seen
	// Opcodes >= 0x2D are not observed in the v2.1 corpus and route to the
	// placeholder path so future SDK additions never panic the decoder.
)

// opcodeNames covers every declared opcode. Bytes not in this map are
// rendered as `<!-- xbf:opcode 0xNN unknown -->`.
var opcodeNames = map[Opcode]string{
	OpEndOfStream:                 "EndOfStream",
	OpLineInfo:                    "LineInfo",
	OpLineInfoAbsolute:            "LineInfoAbsolute",
	OpNamespace:                   "Namespace",
	OpPushScope:                   "PushScope",
	OpPopScope:                    "PopScope",
	OpStartObject:                 "StartObject",
	OpStartObjectFromMember:       "StartObjectFromMember",
	OpEndObject:                   "EndObject",
	OpStartMember:                 "StartMember",
	OpStartMemberFromType:         "StartMemberFromType",
	OpEndMember:                   "EndMember",
	OpAddDirective:                "AddDirective",
	OpAddText:                     "AddText",
	OpStartProperty:               "StartProperty",
	OpEndProperty:                 "EndProperty",
	OpAddValue:                    "AddValue",
	OpSetValue:                    "SetValue",
	OpSetConnectionId:             "SetConnectionId",
	OpSetName:                     "SetName",
	OpGetResourcePropertyBag:      "GetResourcePropertyBag",
	OpProvideValue:                "ProvideValue",
	OpAddNamespace:                "AddNamespace",
	OpAddDirectiveProperty:        "AddDirectiveProperty",
	OpStartConditionalScope:       "StartConditionalScope",
	OpEndConditionalScope:         "EndConditionalScope",
	OpStartObjectWithName:         "StartObjectWithName",
	OpEndObjectWithName:           "EndObjectWithName",
	OpDeferredElement:             "DeferredElement",
	OpStaticResource:              "StaticResource",
	OpThemeResource:               "ThemeResource",
	OpCustomBindingExpression:     "CustomBindingExpression",
	OpTemplateBinding:             "TemplateBinding",
	OpStreamOffsetMarker:          "StreamOffsetMarker",
	OpEndOfAttributes:             "EndOfAttributes",
	OpDeferredResourceDictionary:  "DeferredResourceDictionary",
	OpResourceDictionaryReference: "ResourceDictionaryReference",
	OpXNameReference:              "XNameReference",
	OpXNameDirective:              "XNameDirective",
	OpStaticResourceReference:     "StaticResourceReference",
	OpThemeResourceReference:      "ThemeResourceReference",
	OpResourceDictionaryEnd:       "ResourceDictionaryEnd",
	OpExtensionPoint:              "ExtensionPoint",
	OpUnknownReserved2C:           "Reserved2C",
}

// IsKnownOpcode reports whether op is in the enumerated v2.1 set.
func IsKnownOpcode(op Opcode) bool {
	_, ok := opcodeNames[op]
	return ok
}
