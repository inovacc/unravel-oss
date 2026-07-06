package types

import (
	"fmt"
	"strings"
)

// ParseClassSignature parses a class signature (JVMS §4.7.9.1).
// Format: <FormalTypeParams>? SuperclassSignature SuperinterfaceSignature*
func ParseClassSignature(sig string) (*ClassSignature, error) {
	p := &sigParser{data: sig}

	var formalParams []FormalTypeParam

	if p.peek() == '<' {
		var err error

		formalParams, err = p.parseFormalTypeParams()
		if err != nil {
			return nil, fmt.Errorf("parsing class signature: %w", err)
		}
	}

	superClass, err := p.parseClassTypeSignature()
	if err != nil {
		return nil, fmt.Errorf("parsing superclass: %w", err)
	}

	var ifaces []JavaType

	for !p.eof() {
		iface, err := p.parseClassTypeSignature()
		if err != nil {
			return nil, fmt.Errorf("parsing interface: %w", err)
		}

		ifaces = append(ifaces, iface)
	}

	return &ClassSignature{
		FormalParams: formalParams,
		SuperClass:   superClass,
		Interfaces:   ifaces,
	}, nil
}

// ParseMethodSignature parses a method type signature (JVMS §4.7.9.1).
// Format: <FormalTypeParams>? ( TypeSignature* ) ReturnType ThrowsSignature*
func ParseMethodSignature(sig string) (*MethodSignature, error) {
	p := &sigParser{data: sig}

	var formalParams []FormalTypeParam

	if p.peek() == '<' {
		var err error

		formalParams, err = p.parseFormalTypeParams()
		if err != nil {
			return nil, fmt.Errorf("parsing method signature: %w", err)
		}
	}

	if !p.consume('(') {
		return nil, fmt.Errorf("expected '(' in method signature: %q", sig)
	}

	var paramTypes []JavaType

	for p.peek() != ')' {
		pt, err := p.parseTypeSignature()
		if err != nil {
			return nil, fmt.Errorf("parsing param type: %w", err)
		}

		paramTypes = append(paramTypes, pt)
	}

	p.consume(')')

	var returnType JavaType

	if p.peek() == 'V' {
		p.advance()

		returnType = TypeVoid
	} else {
		var err error

		returnType, err = p.parseTypeSignature()
		if err != nil {
			return nil, fmt.Errorf("parsing return type: %w", err)
		}
	}

	var exceptions []JavaType

	for p.peek() == '^' {
		p.advance()

		exc, err := p.parseTypeSignature()
		if err != nil {
			return nil, fmt.Errorf("parsing throws: %w", err)
		}

		exceptions = append(exceptions, exc)
	}

	return &MethodSignature{
		FormalParams: formalParams,
		ParamTypes:   paramTypes,
		ReturnType:   returnType,
		Exceptions:   exceptions,
	}, nil
}

// ParseFieldSignature parses a field type signature into a JavaType.
func ParseFieldSignature(sig string) (JavaType, error) {
	p := &sigParser{data: sig}

	t, err := p.parseTypeSignature()
	if err != nil {
		return nil, fmt.Errorf("parsing field signature: %w", err)
	}

	return t, nil
}

// sigParser is a simple recursive descent parser for JVM generic signatures.
type sigParser struct {
	data string
	pos  int
}

func (p *sigParser) eof() bool { return p.pos >= len(p.data) }
func (p *sigParser) peek() byte {
	if p.eof() {
		return 0
	}

	return p.data[p.pos]
}
func (p *sigParser) advance() byte { b := p.data[p.pos]; p.pos++; return b }

func (p *sigParser) consume(expected byte) bool {
	if p.peek() == expected {
		p.advance()
		return true
	}

	return false
}

// parseFormalTypeParams parses <Ident:ClassBound:InterfaceBound*>
func (p *sigParser) parseFormalTypeParams() ([]FormalTypeParam, error) {
	if !p.consume('<') {
		return nil, fmt.Errorf("expected '<'")
	}

	var params []FormalTypeParam

	for p.peek() != '>' && !p.eof() {
		ftp, err := p.parseFormalTypeParam()
		if err != nil {
			return nil, err
		}

		params = append(params, ftp)
	}

	if !p.consume('>') {
		return nil, fmt.Errorf("expected '>'")
	}

	return params, nil
}

func (p *sigParser) parseFormalTypeParam() (FormalTypeParam, error) {
	name := p.readIdentifier()
	if name == "" {
		return FormalTypeParam{}, fmt.Errorf("expected type parameter name at pos %d", p.pos)
	}

	if !p.consume(':') {
		return FormalTypeParam{}, fmt.Errorf("expected ':' after type parameter name %q", name)
	}

	ftp := FormalTypeParam{ParamName: name}

	// Class bound (may be empty if next is ':')
	if p.peek() != ':' && p.peek() != '>' {
		classBound, err := p.parseTypeSignature()
		if err != nil {
			return ftp, fmt.Errorf("parsing class bound: %w", err)
		}

		ftp.ClassBound = classBound
	}

	// Interface bounds
	for p.consume(':') {
		ifaceBound, err := p.parseTypeSignature()
		if err != nil {
			return ftp, fmt.Errorf("parsing interface bound: %w", err)
		}

		ftp.InterfaceBounds = append(ftp.InterfaceBounds, ifaceBound)
	}

	return ftp, nil
}

func (p *sigParser) parseTypeSignature() (JavaType, error) {
	switch p.peek() {
	case 'B':
		p.advance()
		return TypeByte, nil
	case 'C':
		p.advance()
		return TypeChar, nil
	case 'D':
		p.advance()
		return TypeDouble, nil
	case 'F':
		p.advance()
		return TypeFloat, nil
	case 'I':
		p.advance()
		return TypeInt, nil
	case 'J':
		p.advance()
		return TypeLong, nil
	case 'S':
		p.advance()
		return TypeShort, nil
	case 'Z':
		p.advance()
		return TypeBoolean, nil
	case 'V':
		p.advance()
		return TypeVoid, nil
	case 'L':
		return p.parseClassTypeSignature()
	case 'T':
		return p.parseTypeVariableSignature()
	case '[':
		return p.parseArrayTypeSignature()
	case '+', '-', '*':
		return p.parseWildcardIndicator()
	default:
		return nil, fmt.Errorf("unexpected char %q at pos %d in %q", string(p.peek()), p.pos, p.data)
	}
}

func (p *sigParser) parseClassTypeSignature() (JavaType, error) {
	if !p.consume('L') {
		return nil, fmt.Errorf("expected 'L' at pos %d", p.pos)
	}

	// Read the class name (internal form, using '/' as separator)
	var nameParts []string

	nameParts = append(nameParts, p.readClassNameSegment())

	for p.peek() == '/' {
		p.advance()
		nameParts = append(nameParts, p.readClassNameSegment())
	}

	className := strings.Join(nameParts, ".")

	// Check for type arguments
	var typeArgs []JavaType

	if p.peek() == '<' {
		p.advance()

		for p.peek() != '>' && !p.eof() {
			arg, err := p.parseTypeArgument()
			if err != nil {
				return nil, err
			}

			typeArgs = append(typeArgs, arg)
		}

		if !p.consume('>') {
			return nil, fmt.Errorf("expected '>' after type arguments")
		}
	}

	// Handle inner class suffixes (e.g. Foo.Bar<X>)
	for p.peek() == '.' {
		p.advance()
		inner := p.readClassNameSegment()
		className = className + "." + inner

		if p.peek() == '<' {
			p.advance()

			typeArgs = nil

			for p.peek() != '>' && !p.eof() {
				arg, err := p.parseTypeArgument()
				if err != nil {
					return nil, err
				}

				typeArgs = append(typeArgs, arg)
			}

			if !p.consume('>') {
				return nil, fmt.Errorf("expected '>' after inner type arguments")
			}
		}
	}

	if !p.consume(';') {
		return nil, fmt.Errorf("expected ';' at pos %d in %q", p.pos, p.data)
	}

	base := NewRefType(className)
	if len(typeArgs) > 0 {
		return NewGenericType(base, typeArgs...), nil
	}

	return base, nil
}

func (p *sigParser) parseTypeArgument() (JavaType, error) {
	switch p.peek() {
	case '*':
		p.advance()
		return NewWildcard(), nil
	case '+':
		p.advance()

		bound, err := p.parseTypeSignature()
		if err != nil {
			return nil, err
		}

		return NewWildcardExtends(bound), nil
	case '-':
		p.advance()

		bound, err := p.parseTypeSignature()
		if err != nil {
			return nil, err
		}

		return NewWildcardSuper(bound), nil
	default:
		return p.parseTypeSignature()
	}
}

func (p *sigParser) parseWildcardIndicator() (JavaType, error) {
	switch p.peek() {
	case '*':
		p.advance()
		return NewWildcard(), nil
	case '+':
		p.advance()

		bound, err := p.parseTypeSignature()
		if err != nil {
			return nil, err
		}

		return NewWildcardExtends(bound), nil
	case '-':
		p.advance()

		bound, err := p.parseTypeSignature()
		if err != nil {
			return nil, err
		}

		return NewWildcardSuper(bound), nil
	default:
		return nil, fmt.Errorf("expected wildcard indicator at pos %d", p.pos)
	}
}

func (p *sigParser) parseTypeVariableSignature() (JavaType, error) {
	if !p.consume('T') {
		return nil, fmt.Errorf("expected 'T' at pos %d", p.pos)
	}

	name := p.readUntil(';')
	if !p.consume(';') {
		return nil, fmt.Errorf("expected ';' after type variable name")
	}

	return NewTypeVariable(name), nil
}

func (p *sigParser) parseArrayTypeSignature() (JavaType, error) {
	dims := 0

	for p.peek() == '[' {
		p.advance()

		dims++
	}

	elem, err := p.parseTypeSignature()
	if err != nil {
		return nil, err
	}

	return NewArrayType(dims, elem), nil
}

func (p *sigParser) readIdentifier() string {
	start := p.pos
	for !p.eof() {
		ch := p.peek()
		if ch == ':' || ch == '<' || ch == '>' || ch == ';' || ch == '/' || ch == '.' {
			break
		}

		p.advance()
	}

	return p.data[start:p.pos]
}

func (p *sigParser) readClassNameSegment() string {
	start := p.pos
	for !p.eof() {
		ch := p.peek()
		if ch == '/' || ch == '<' || ch == '>' || ch == ';' || ch == '.' {
			break
		}

		p.advance()
	}

	return p.data[start:p.pos]
}

func (p *sigParser) readUntil(stop byte) string {
	start := p.pos
	for !p.eof() && p.peek() != stop {
		p.advance()
	}

	return p.data[start:p.pos]
}
