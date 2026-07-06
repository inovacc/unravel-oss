package ast

import (
	"regexp"
	"strings"
)

// Builder creates a C++ semantic AST from parsed source text.
// This is a simplified builder that works from source text rather than
// a full ANTLR4 parse tree, providing basic structural extraction.
// For full fidelity, use the ANTLR4 visitor-based builder in the parser package.
type Builder struct{}

// NewBuilder creates a new AST builder.
func NewBuilder() *Builder {
	return &Builder{}
}

// BuildFromSource creates a TranslationUnit from C++ source text.
// It extracts includes, namespaces, classes, functions, and other
// top-level declarations using pattern matching.
func (b *Builder) BuildFromSource(filename string, source string) *TranslationUnit {
	tu := &TranslationUnit{
		FileName: filename,
	}

	lines := strings.Split(source, "\n")
	tu.Includes = b.extractIncludes(lines)
	tu.Decls = b.extractTopLevelDecls(source, lines)

	return tu
}

var includeRe = regexp.MustCompile(`^\s*#\s*include\s+([<"])([^>"]+)[>"]`)

// extractIncludes finds all #include directives.
func (b *Builder) extractIncludes(lines []string) []*Include {
	var includes []*Include

	for i, line := range lines {
		match := includeRe.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		inc := &Include{
			baseNode: baseNode{Position: Position{Line: i + 1, Column: 1}},
			Path:     match[2],
			System:   match[1] == "<",
		}

		includes = append(includes, inc)
	}

	return includes
}

var (
	// classRe captures: optional template, class/struct/union, name, optional inheritance list
	classRe     = regexp.MustCompile(`(?m)^\s*(template\s*<[^>]*>\s*)?(class|struct|union)\s+(\w+)\s*(?::\s*([^{;]+))?`)
	enumRe      = regexp.MustCompile(`(?m)^\s*enum\s+(class\s+)?(\w+)`)
	namespaceRe = regexp.MustCompile(`(?m)^\s*namespace\s+(\w+)`)
	typedefRe   = regexp.MustCompile(`(?m)^\s*(?:typedef\s+(.+?)\s+(\w+)\s*;|using\s+(\w+)\s*=\s*(.+?)\s*;)`)
	usingRe     = regexp.MustCompile(`(?m)^\s*using\s+(namespace\s+)?(\w[\w:]*)\s*;`)

	// functionRe matches free function declarations in headers:
	//   ReturnType funcName(params);
	//   ReturnType funcName(params) { ... }
	// Avoids matching keywords (if, for, while, return, etc.) and class forward declarations.
	functionRe = regexp.MustCompile(`(?m)^([\w:*&<> ]+?)\s+(\w+)\s*\(([^)]*)\)\s*(?:const\s*)?[;{]`)

	// pureVirtualRe matches pure virtual method declarations: virtual ... = 0;
	pureVirtualRe = regexp.MustCompile(`(?m)virtual\s+([\w:*&<> ]+?)\s+(\w+)\s*\(([^)]*)\)\s*(?:const\s*)?(?:override\s*)?=\s*0\s*;`)

	// funcPtrTypedefRe matches: typedef RetType (*Name)(Params);
	funcPtrTypedefRe = regexp.MustCompile(`(?m)^\s*typedef\s+([\w\s*]+?)\s*\(\s*\*\s*(\w+)\s*\)\s*\(([^)]*)\)\s*;`)

	// externDeclRe matches: extern "C" { or extern Type name;
	externDeclRe = regexp.MustCompile(`(?m)^\s*extern\s+(?:"C"\s*\{|(\w[\w\s*&]+)\s+(\w+)\s*;)`)

	// gotoRe matches: goto label;
	gotoRe = regexp.MustCompile(`(?m)\bgoto\s+(\w+)\s*;`)

	// labelRe matches: label: followed by space/newline/end (avoids matching :: scope resolution)
	labelRe = regexp.MustCompile(`(?m)^(\w+)\s*:[^:]`)

	// functionKeywords are C/C++ keywords that should not be matched as function names.
	functionKeywords = map[string]struct{}{
		"if": {}, "else": {}, "for": {}, "while": {}, "do": {},
		"switch": {}, "case": {}, "return": {}, "class": {}, "struct": {},
		"union": {}, "enum": {}, "namespace": {}, "typedef": {}, "using": {},
		"template": {}, "virtual": {}, "static": {}, "extern": {},
		"public": {}, "private": {}, "protected": {}, "new": {}, "delete": {},
		"throw": {}, "catch": {}, "try": {}, "sizeof": {}, "typeof": {},
		"include": {}, "define": {}, "ifdef": {}, "ifndef": {}, "endif": {},
		"goto": {},
	}
)

// extractTopLevelDecls extracts top-level declarations from source.
func (b *Builder) extractTopLevelDecls(source string, lines []string) []Node {
	var decls []Node

	// Extract function pointer typedefs (before regular typedefs to avoid conflict)
	for _, match := range funcPtrTypedefRe.FindAllStringSubmatchIndex(source, -1) {
		line := countLines(source, match[0])
		retType := strings.TrimSpace(source[match[2]:match[3]])
		name := source[match[4]:match[5]]

		paramStr := ""
		if match[6] != -1 && match[7] != -1 {
			paramStr = source[match[6]:match[7]]
		}

		fpd := &FuncPtrDecl{
			baseNode:   baseNode{Position: Position{Line: line, Column: 1}},
			Name:       name,
			ReturnType: ParseTypeRef(retType),
			Params:     parseParameters(paramStr),
		}

		decls = append(decls, fpd)
	}

	// Extract extern declarations
	for _, match := range externDeclRe.FindAllStringSubmatchIndex(source, -1) {
		line := countLines(source, match[0])

		ed := &ExternDecl{
			baseNode: baseNode{Position: Position{Line: line, Column: 1}},
		}

		// Check if it's extern "C" { or extern Type name;
		if match[2] != -1 && match[3] != -1 {
			// extern Type name;
			typeName := strings.TrimSpace(source[match[2]:match[3]])
			varName := source[match[4]:match[5]]
			ed.Var = &Variable{
				baseNode: baseNode{Position: Position{Line: line, Column: 1}},
				Name:     varName,
				Type:     ParseTypeRef(typeName),
			}
		} else {
			ed.Linkage = "C"
		}

		decls = append(decls, ed)
	}

	// Extract using declarations
	for _, match := range usingRe.FindAllStringSubmatchIndex(source, -1) {
		line := countLines(source, match[0])
		isNamespace := match[2] != -1 && match[3] != -1 && source[match[2]:match[3]] != ""
		name := source[match[4]:match[5]]

		decls = append(decls, &UsingDecl{
			baseNode:  baseNode{Position: Position{Line: line, Column: 1}},
			Name:      name,
			Namespace: isNamespace,
		})
	}

	// Extract typedef/using alias declarations
	for _, match := range typedefRe.FindAllStringSubmatch(source, -1) {
		idx := typedefRe.FindStringIndex(source)

		line := 1
		if idx != nil {
			line = countLines(source, idx[0])
		}

		td := &TypedefDecl{
			baseNode: baseNode{Position: Position{Line: line, Column: 1}},
		}

		if match[2] != "" {
			// typedef form
			td.Name = match[2]
			td.Underlying = &TypeRef{Name: strings.TrimSpace(match[1])}
		} else {
			// using alias form
			td.Name = match[3]
			td.Underlying = &TypeRef{Name: strings.TrimSpace(match[4])}
		}

		decls = append(decls, td)
	}

	// Extract enum declarations
	for _, match := range enumRe.FindAllStringSubmatchIndex(source, -1) {
		line := countLines(source, match[0])
		scoped := match[2] != match[3] && source[match[2]:match[3]] != ""
		name := source[match[4]:match[5]]

		decls = append(decls, &Enum{
			baseNode: baseNode{Position: Position{Line: line, Column: 1}},
			Name:     name,
			Scoped:   scoped,
		})
	}

	// Extract class/struct/union declarations (with inheritance)
	for _, match := range classRe.FindAllStringSubmatchIndex(source, -1) {
		line := countLines(source, match[0])
		kindStr := source[match[4]:match[5]]
		name := source[match[6]:match[7]]

		kind := ClassKindClass

		switch kindStr {
		case "struct":
			kind = ClassKindStruct
		case "union":
			kind = ClassKindUnion
		}

		cls := &Class{
			baseNode: baseNode{Position: Position{Line: line, Column: 1}},
			Kind:     kind,
			Name:     name,
		}

		// Check for template parameters
		if match[2] != -1 && match[3] != -1 && match[2] != match[3] {
			tplText := source[match[2]:match[3]]
			cls.TemplateParams = parseTemplateParams(tplText)
		}

		// Parse base class list (e.g., "public Base, private Other")
		if match[8] != -1 && match[9] != -1 {
			baseList := source[match[8]:match[9]]
			cls.BaseClasses = parseBaseClasses(baseList)
		}

		// Scan the class body for pure virtual methods
		cls.Methods = b.extractPureVirtualMethods(source, match[0])

		decls = append(decls, cls)
	}

	// Extract free function declarations
	b.extractFunctions(source, &decls)

	// Extract namespace declarations
	for _, match := range namespaceRe.FindAllStringSubmatchIndex(source, -1) {
		line := countLines(source, match[0])
		name := source[match[2]:match[3]]

		decls = append(decls, &Namespace{
			baseNode: baseNode{Position: Position{Line: line, Column: 1}},
			Name:     name,
		})
	}

	_ = lines // available for line-by-line analysis if needed

	return decls
}

// parseTemplateParams extracts template parameter names from a template<...> clause.
func parseTemplateParams(text string) []*TemplateParam {
	// Strip "template" prefix and angle brackets
	text = strings.TrimSpace(text)
	if idx := strings.Index(text, "<"); idx >= 0 {
		text = text[idx+1:]
	}

	if idx := strings.LastIndex(text, ">"); idx >= 0 {
		text = text[:idx]
	}

	var params []*TemplateParam

	for part := range strings.SplitSeq(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		fields := strings.Fields(part)
		p := &TemplateParam{}

		switch {
		case len(fields) >= 2:
			p.Kind = fields[0]
			p.Name = fields[1]
		case len(fields) == 1:
			p.Kind = "typename"
			p.Name = fields[0]
		}

		params = append(params, p)
	}

	return params
}

// countLines returns the 1-based line number of offset in source.
func countLines(source string, offset int) int {
	return strings.Count(source[:offset], "\n") + 1
}

// ParseTypeRef parses a type reference string into a TypeRef.
func ParseTypeRef(typeStr string) *TypeRef {
	typeStr = strings.TrimSpace(typeStr)
	if typeStr == "" {
		return &TypeRef{Name: "void"}
	}

	ref := &TypeRef{}

	// Check for const
	if strings.HasPrefix(typeStr, "const ") {
		ref.Const = true
		typeStr = strings.TrimPrefix(typeStr, "const ")
		typeStr = strings.TrimSpace(typeStr)
	}

	// Check for trailing const
	if strings.HasSuffix(typeStr, " const") {
		ref.Const = true
		typeStr = strings.TrimSuffix(typeStr, " const")
		typeStr = strings.TrimSpace(typeStr)
	}

	// Check for pointer
	if strings.HasSuffix(typeStr, "*") {
		ref.Pointer = true
		typeStr = strings.TrimSuffix(typeStr, "*")
		typeStr = strings.TrimSpace(typeStr)
	}

	// Check for rvalue reference
	if strings.HasSuffix(typeStr, "&&") {
		ref.RValueRef = true
		typeStr = strings.TrimSuffix(typeStr, "&&")
		typeStr = strings.TrimSpace(typeStr)
	} else if strings.HasSuffix(typeStr, "&") {
		ref.Reference = true
		typeStr = strings.TrimSuffix(typeStr, "&")
		typeStr = strings.TrimSpace(typeStr)
	}

	// Parse template arguments
	if idx := strings.Index(typeStr, "<"); idx >= 0 {
		endIdx := strings.LastIndex(typeStr, ">")
		if endIdx > idx+1 {
			ref.Name = typeStr[:idx]
			argsStr := typeStr[idx+1 : endIdx]
			ref.TemplateArgs = parseTemplateArgs(argsStr)
		} else {
			ref.Name = typeStr
		}
	} else {
		ref.Name = typeStr
	}

	return ref
}

// parseBaseClasses parses a base class list like "public Base, private Other".
func parseBaseClasses(text string) []*BaseClass {
	var bases []*BaseClass

	depth := 0

	parts := splitBaseClasses(text, depth)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		bc := &BaseClass{Access: "private"} // default for class
		fields := strings.Fields(part)

		switch {
		case len(fields) >= 2 && isAccessSpec(fields[0]):
			bc.Access = fields[0]
			bc.Name = fields[len(fields)-1]
		case len(fields) >= 1:
			bc.Name = fields[len(fields)-1]
		}

		if bc.Name != "" {
			bases = append(bases, bc)
		}
	}

	return bases
}

// splitBaseClasses splits a comma-separated base list respecting template angle brackets.
func splitBaseClasses(text string, _ int) []string {
	var parts []string

	depth := 0
	start := 0

	for i := range len(text) {
		switch text[i] {
		case '<':
			depth++
		case '>':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, text[start:i])
				start = i + 1
			}
		}
	}

	if start < len(text) {
		parts = append(parts, text[start:])
	}

	return parts
}

func isAccessSpec(s string) bool {
	return s == "public" || s == "private" || s == "protected"
}

// extractPureVirtualMethods scans from a class declaration offset for pure virtual methods.
func (b *Builder) extractPureVirtualMethods(source string, classOffset int) []*Method {
	// Find the opening brace of the class body
	braceIdx := strings.Index(source[classOffset:], "{")
	if braceIdx == -1 {
		return nil
	}

	bodyStart := classOffset + braceIdx + 1

	// Find matching closing brace
	depth := 1

	bodyEnd := bodyStart
	for bodyEnd < len(source) && depth > 0 {
		switch source[bodyEnd] {
		case '{':
			depth++
		case '}':
			depth--
		}

		bodyEnd++
	}

	if depth != 0 {
		return nil
	}

	body := source[bodyStart:bodyEnd]

	var methods []*Method

	for _, m := range pureVirtualRe.FindAllStringSubmatch(body, -1) {
		method := &Method{
			Name:    m[2],
			Virtual: true,
			Pure:    true,
		}
		if m[1] != "" {
			method.ReturnType = ParseTypeRef(strings.TrimSpace(m[1]))
		}

		methods = append(methods, method)
	}

	return methods
}

// extractFunctions finds free function declarations/definitions in source.
func (b *Builder) extractFunctions(source string, decls *[]Node) {
	// Track which names are classes to avoid duplicating them
	classNames := make(map[string]struct{})

	for _, d := range *decls {
		if cls, ok := d.(*Class); ok {
			classNames[cls.Name] = struct{}{}
		}
	}

	for _, match := range functionRe.FindAllStringSubmatchIndex(source, -1) {
		retType := strings.TrimSpace(source[match[2]:match[3]])
		name := source[match[4]:match[5]]

		// Skip keywords, class names, and method definitions (Class::method)
		if _, ok := functionKeywords[name]; ok {
			continue
		}

		if _, ok := classNames[name]; ok {
			continue
		}

		if strings.Contains(name, "::") {
			continue
		}
		// Skip if return type looks like a keyword/declaration
		if _, ok := functionKeywords[retType]; ok {
			continue
		}

		line := countLines(source, match[0])
		fn := &Function{
			baseNode:   baseNode{Position: Position{Line: line, Column: 1}},
			Name:       name,
			ReturnType: ParseTypeRef(retType),
		}

		// Parse parameters
		if match[6] != -1 && match[7] != -1 {
			paramStr := source[match[6]:match[7]]
			fn.Params = parseParameters(paramStr)
		}

		*decls = append(*decls, fn)
	}
}

// parseParameters parses a comma-separated parameter list.
func parseParameters(text string) []*Parameter {
	text = strings.TrimSpace(text)
	if text == "" || text == "void" {
		return nil
	}

	var params []*Parameter

	depth := 0
	start := 0

	for i := range len(text) {
		switch text[i] {
		case '<', '(':
			depth++
		case '>', ')':
			depth--
		case ',':
			if depth == 0 {
				if p := parseOneParam(text[start:i]); p != nil {
					params = append(params, p)
				}

				start = i + 1
			}
		}
	}

	if p := parseOneParam(text[start:]); p != nil {
		params = append(params, p)
	}

	return params
}

// parseOneParam parses a single "type name" or "type" parameter.
func parseOneParam(text string) *Parameter {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	// Split from the right to handle "const std::string& name"
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return nil
	}

	p := &Parameter{}
	if len(fields) >= 2 {
		p.Name = fields[len(fields)-1]
		// Strip name from end if it looks like an identifier (not * or &)
		if strings.ContainsAny(p.Name, "*&<>") {
			// Entire text is the type with no name
			p.Type = ParseTypeRef(text)
			p.Name = ""
		} else {
			p.Type = ParseTypeRef(strings.Join(fields[:len(fields)-1], " "))
		}
	} else {
		p.Type = ParseTypeRef(text)
	}

	return p
}

// parseTemplateArgs parses comma-separated template arguments.
func parseTemplateArgs(args string) []*TypeRef {
	var result []*TypeRef

	depth := 0
	start := 0

	for i, ch := range args {
		switch ch {
		case '<':
			depth++
		case '>':
			depth--
		case ',':
			if depth == 0 {
				result = append(result, ParseTypeRef(args[start:i]))
				start = i + 1
			}
		}
	}

	if start < len(args) {
		result = append(result, ParseTypeRef(args[start:]))
	}

	return result
}
