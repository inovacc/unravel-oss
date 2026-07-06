/*
Copyright (c) 2026 Security Research
*/

package xbf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxDepth caps the node-stream tree depth (T-04-04 mitigation).
const MaxDepth = 64

// MaxNodes is a hard ceiling on decoded node count to bound DoS via long
// streams. 1M nodes is well above any sane XAML.
const MaxNodes = 1 << 20

// Node is a single entry in the decoded node tree.
type Node struct {
	Op              Opcode
	TypeIdx         int    // -1 if not applicable
	PropIdx         int    // -1 if not applicable
	StringIdx       int    // -1 if not applicable
	XmlNsIdx        int    // -1 if not applicable
	Value           string // for OpSetValue / OpAddText / OpAddNamespace prefix etc.
	NamespaceURI    string
	NamespacePrefix string
	Name            string // resolved type or property name (lookup at decode time)
	Children        []*Node
	// Properties are attribute-style children (StartProperty/SetValue/EndProperty).
	Properties  []*Node
	Unknown     bool
	UnknownByte byte
}

// NodeTree is the decoded tree plus traversal stats.
type NodeTree struct {
	Root           *Node
	Stats          DecodeStats
	UnknownOpcodes []byte
	warnings       []string
}

// Warnings returns a copy of the soft errors collected during decode.
func (t *NodeTree) Warnings() []string {
	if t == nil {
		return nil
	}
	out := make([]string, len(t.warnings))
	copy(out, t.warnings)
	return out
}

// DecodeStats summarizes traversal stats for monitoring + tests.
type DecodeStats struct {
	NodesDecoded int
	UnknownNodes int
	DepthMax     int
}

// decoderState carries running decoder context.
type decoderState struct {
	r           io.Reader
	tables      *Tables
	root        *Node
	stack       []*Node // current open object stack (for objects)
	depth       int
	tree        *NodeTree
	currentProp *Node   // active property (between StartProperty/EndProperty)
	pendingNS   []*Node // namespaces declared at top of file before any object
	unknownSet  map[byte]bool
}

// DecodeNodeStream reads the node stream from r, dispatching opcodes to
// handlers. Unknown opcodes do NOT abort the stream — they are recorded as
// placeholder nodes and collection on tree.UnknownOpcodes.
func DecodeNodeStream(r io.Reader, tables *Tables) (*NodeTree, error) {
	if tables == nil {
		return nil, errors.New("nil tables")
	}
	tree := &NodeTree{}
	d := &decoderState{
		r:          r,
		tables:     tables,
		tree:       tree,
		unknownSet: map[byte]bool{},
	}
	for {
		var b [1]byte
		_, err := io.ReadFull(r, b[:])
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read opcode: %w", err)
		}
		op := Opcode(b[0])
		if op == OpEndOfStream {
			break
		}
		if d.tree.Stats.NodesDecoded >= MaxNodes {
			d.tree.warnings = append(d.tree.warnings, "max node count reached; truncating")
			break
		}
		if err := d.dispatch(op); err != nil {
			// Per D-08, transient stream-read errors during operand fetch are
			// surfaced as warnings (placeholder behavior) rather than aborting.
			d.tree.warnings = append(d.tree.warnings, fmt.Sprintf("dispatch op 0x%02X: %v", byte(op), err))
			break
		}
	}
	tree.UnknownOpcodes = sortedKeys(d.unknownSet)
	return tree, nil
}

// dispatch routes opcodes to their handlers or to the placeholder path.
func (d *decoderState) dispatch(op Opcode) error {
	d.tree.Stats.NodesDecoded++
	if !IsKnownOpcode(op) {
		return d.handleUnknown(op)
	}
	switch op {
	case OpStartObject, OpStartObjectWithName, OpStartObjectFromMember:
		return d.handleStartObject(op)
	case OpEndObject, OpEndObjectWithName:
		d.handleEndObject(op)
		return nil
	case OpStartProperty, OpStartMember, OpStartMemberFromType:
		return d.handleStartProperty(op)
	case OpEndProperty, OpEndMember:
		d.handleEndProperty()
		return nil
	case OpSetValue, OpAddValue, OpAddText:
		return d.handleSetValue(op)
	case OpNamespace, OpAddNamespace:
		return d.handleAddNamespace(op)
	case OpEndOfStream:
		return nil
	default:
		// Known opcode without a handler: record as a no-op metadata node.
		// This keeps the dispatcher total over the enumerated set.
		return nil
	}
}

func (d *decoderState) handleStartObject(op Opcode) error {
	idx, err := d.readU16()
	if err != nil {
		return err
	}
	n := &Node{
		Op:        op,
		TypeIdx:   int(idx),
		PropIdx:   -1,
		StringIdx: -1,
		XmlNsIdx:  -1,
		Name:      d.tables.TypeName(int(idx)),
	}
	if int(idx) >= len(d.tables.Types) {
		d.tree.warnings = append(d.tree.warnings, fmt.Sprintf("StartObject type idx %d out of range", idx))
	}
	// Attach pending namespace declarations to the first object encountered.
	if d.root == nil && len(d.pendingNS) > 0 {
		n.Properties = append(n.Properties, d.pendingNS...)
		d.pendingNS = nil
	}
	if d.root == nil {
		d.root = n
		d.tree.Root = n
	} else if d.currentProp != nil {
		d.currentProp.Children = append(d.currentProp.Children, n)
	} else if len(d.stack) > 0 {
		parent := d.stack[len(d.stack)-1]
		parent.Children = append(parent.Children, n)
	}
	d.stack = append(d.stack, n)
	d.depth++
	if d.depth > d.tree.Stats.DepthMax {
		d.tree.Stats.DepthMax = d.depth
	}
	if d.depth > MaxDepth {
		d.tree.warnings = append(d.tree.warnings, "max recursion depth reached; unwinding")
		// Unwind: pop everything except root, set sentinel that prevents further
		// pushes by returning error from the caller dispatch loop.
		for len(d.stack) > 1 {
			d.stack = d.stack[:len(d.stack)-1]
			d.depth--
		}
		return errors.New("max depth exceeded")
	}
	return nil
}

func (d *decoderState) handleEndObject(_ Opcode) {
	if len(d.stack) > 0 {
		d.stack = d.stack[:len(d.stack)-1]
		d.depth--
	}
}

func (d *decoderState) handleStartProperty(op Opcode) error {
	idx, err := d.readU16()
	if err != nil {
		return err
	}
	n := &Node{
		Op:        op,
		TypeIdx:   -1,
		PropIdx:   int(idx),
		StringIdx: -1,
		XmlNsIdx:  -1,
		Name:      d.tables.PropertyName(int(idx)),
	}
	if int(idx) >= len(d.tables.Properties) {
		d.tree.warnings = append(d.tree.warnings, fmt.Sprintf("StartProperty idx %d out of range", idx))
	}
	if len(d.stack) > 0 {
		parent := d.stack[len(d.stack)-1]
		parent.Properties = append(parent.Properties, n)
	}
	d.currentProp = n
	return nil
}

func (d *decoderState) handleEndProperty() {
	d.currentProp = nil
}

func (d *decoderState) handleSetValue(op Opcode) error {
	idx, err := d.readU16()
	if err != nil {
		return err
	}
	val := d.tables.String(int(idx))
	if int(idx) >= len(d.tables.Strings) {
		d.tree.warnings = append(d.tree.warnings, fmt.Sprintf("SetValue string idx %d out of range", idx))
	}
	n := &Node{
		Op:        op,
		TypeIdx:   -1,
		PropIdx:   -1,
		StringIdx: int(idx),
		XmlNsIdx:  -1,
		Value:     val,
	}
	if d.currentProp != nil {
		d.currentProp.Value = val
		d.currentProp.StringIdx = int(idx)
		return nil
	}
	if len(d.stack) > 0 {
		parent := d.stack[len(d.stack)-1]
		parent.Children = append(parent.Children, n)
	}
	return nil
}

func (d *decoderState) handleAddNamespace(op Opcode) error {
	prefixIdx, err := d.readU16()
	if err != nil {
		return err
	}
	uriIdx, err := d.readU16()
	if err != nil {
		return err
	}
	prefix := d.tables.String(int(prefixIdx))
	uri := d.tables.String(int(uriIdx))
	n := &Node{
		Op:              op,
		TypeIdx:         -1,
		PropIdx:         -1,
		StringIdx:       int(uriIdx),
		XmlNsIdx:        -1,
		Value:           uri,
		NamespacePrefix: prefix,
		NamespaceURI:    uri,
	}
	if d.root == nil {
		d.pendingNS = append(d.pendingNS, n)
	} else {
		// Attach to root (declared at the topmost element where first used).
		d.root.Properties = append(d.root.Properties, n)
	}
	return nil
}

func (d *decoderState) handleUnknown(op Opcode) error {
	d.tree.Stats.UnknownNodes++
	d.unknownSet[byte(op)] = true
	d.tree.warnings = append(d.tree.warnings, fmt.Sprintf("unknown opcode 0x%02X", byte(op)))
	n := &Node{
		Op:          op,
		TypeIdx:     -1,
		PropIdx:     -1,
		StringIdx:   -1,
		XmlNsIdx:    -1,
		Unknown:     true,
		UnknownByte: byte(op),
	}
	// Skip-1 strategy: do NOT consume operand bytes; continue with next byte.
	if d.root == nil {
		// Place at synthetic root if no object started yet — we attach it as a
		// pre-root warning node by stashing in pendingNS so the writer can emit
		// the placeholder comment near the top.
		d.pendingNS = append(d.pendingNS, n)
		return nil
	}
	if d.currentProp != nil {
		d.currentProp.Children = append(d.currentProp.Children, n)
		return nil
	}
	if len(d.stack) > 0 {
		parent := d.stack[len(d.stack)-1]
		parent.Children = append(parent.Children, n)
	}
	return nil
}

func (d *decoderState) readU16() (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(d.r, b[:]); err != nil {
		return 0, fmt.Errorf("read u16: %w", err)
	}
	return binary.LittleEndian.Uint16(b[:]), nil
}

func sortedKeys(m map[byte]bool) []byte {
	out := make([]byte, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// insertion sort (small N).
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
