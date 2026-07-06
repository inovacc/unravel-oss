package types

import (
	"fmt"
	"strings"
)

// ParseFieldDescriptor parses a JVM field descriptor (JVMS §4.3.2) into a JavaType.
// Examples: "I" → int, "Ljava/lang/String;" → java.lang.String, "[I" → int[], "[[D" → double[][]
func ParseFieldDescriptor(desc string) (JavaType, error) {
	typ, rest, err := parseFieldType(desc)
	if err != nil {
		return nil, err
	}

	if rest != "" {
		return nil, fmt.Errorf("trailing data in field descriptor: %q", rest)
	}

	return typ, nil
}

// ParseMethodDescriptor parses a JVM method descriptor (JVMS §4.3.3) into parameter types and return type.
// Example: "(ILjava/lang/String;)[B" → params: [int, java.lang.String], return: byte[]
func ParseMethodDescriptor(desc string) (params []JavaType, returnType JavaType, err error) {
	if len(desc) == 0 || desc[0] != '(' {
		return nil, nil, fmt.Errorf("method descriptor must start with '(': %q", desc)
	}

	rest := desc[1:]
	for len(rest) > 0 && rest[0] != ')' {
		var param JavaType

		param, rest, err = parseFieldType(rest)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing parameter: %w", err)
		}

		params = append(params, param)
	}

	if len(rest) == 0 || rest[0] != ')' {
		return nil, nil, fmt.Errorf("missing ')' in method descriptor: %q", desc)
	}

	rest = rest[1:] // skip ')'

	if rest == "V" {
		return params, TypeVoid, nil
	}

	returnType, rest, err = parseFieldType(rest)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing return type: %w", err)
	}

	if rest != "" {
		return nil, nil, fmt.Errorf("trailing data after return type: %q", rest)
	}

	return params, returnType, nil
}

func parseFieldType(desc string) (JavaType, string, error) {
	if len(desc) == 0 {
		return nil, "", fmt.Errorf("empty descriptor")
	}

	switch desc[0] {
	case 'B':
		return TypeByte, desc[1:], nil
	case 'C':
		return TypeChar, desc[1:], nil
	case 'D':
		return TypeDouble, desc[1:], nil
	case 'F':
		return TypeFloat, desc[1:], nil
	case 'I':
		return TypeInt, desc[1:], nil
	case 'J':
		return TypeLong, desc[1:], nil
	case 'S':
		return TypeShort, desc[1:], nil
	case 'Z':
		return TypeBoolean, desc[1:], nil
	case 'V':
		return TypeVoid, desc[1:], nil

	case 'L':
		// Object type: Ljava/lang/String;
		semi := strings.IndexByte(desc, ';')
		if semi < 0 {
			return nil, "", fmt.Errorf("unterminated object type: %q", desc)
		}

		internalName := desc[1:semi]

		return NewRefTypeFromInternal(internalName), desc[semi+1:], nil

	case '[':
		// Array type: count leading '[' chars, then parse element type
		dims := 0

		i := 0
		for i < len(desc) && desc[i] == '[' {
			dims++
			i++
		}

		elemType, rest, err := parseFieldType(desc[i:])
		if err != nil {
			return nil, "", fmt.Errorf("parsing array element: %w", err)
		}

		return NewArrayType(dims, elemType), rest, nil

	default:
		return nil, "", fmt.Errorf("unknown descriptor char %q in %q", string(desc[0]), desc)
	}
}

// DescriptorToJava converts a JVM type descriptor to its Java source form.
// e.g. "I" → "int", "Ljava/lang/String;" → "String", "[I" → "int[]"
func DescriptorToJava(desc string) string {
	t, err := ParseFieldDescriptor(desc)
	if err != nil {
		return desc
	}

	return t.Name()
}

// MethodDescriptorToJava converts a method descriptor to a Java-like signature string.
// Returns something like "void foo(int, String)".
func MethodDescriptorToJava(name, desc string) string {
	params, ret, err := ParseMethodDescriptor(desc)
	if err != nil {
		return name + desc
	}

	var b strings.Builder
	b.WriteString(ret.Name())
	b.WriteByte(' ')
	b.WriteString(name)
	b.WriteByte('(')

	for i, p := range params {
		if i > 0 {
			b.WriteString(", ")
		}

		b.WriteString(p.Name())
	}

	b.WriteByte(')')

	return b.String()
}

// CountMethodParams returns the number of parameters in a method descriptor,
// accounting for long/double taking two local variable slots.
func CountMethodParams(desc string) (count int, slots int) {
	params, _, err := ParseMethodDescriptor(desc)
	if err != nil {
		return 0, 0
	}

	count = len(params)
	for _, p := range params {
		slots += p.StackCategory()
	}

	return count, slots
}
