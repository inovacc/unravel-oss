package analysis

// ClassHierarchy represents the inheritance tree of all classes in a codebase.
type ClassHierarchy struct {
	Roots  []*ClassNode          `json:"roots"`   // classes with no parents
	ByName map[string]*ClassNode `json:"by_name"` // all classes indexed by name
}

// ClassNode represents a class in the inheritance hierarchy.
type ClassNode struct {
	Name        string       `json:"name"`
	File        string       `json:"file"`
	Kind        string       `json:"kind"` // class, struct, union
	Parents     []*ClassNode `json:"-"`    // avoid circular JSON
	ParentNames []string     `json:"parents,omitempty"`
	Children    []*ClassNode `json:"-"`
	ChildNames  []string     `json:"children,omitempty"`
	Methods     []string     `json:"methods,omitempty"`
	Fields      []string     `json:"fields,omitempty"`
	HasVirtual  bool         `json:"has_virtual,omitempty"`
	HasPure     bool         `json:"has_pure,omitempty"` // abstract class = Go interface candidate
	IsTemplate  bool         `json:"is_template,omitempty"`
}

// BuildHierarchy constructs a class inheritance tree from the symbol table.
func BuildHierarchy(symbols *SymbolTable) *ClassHierarchy {
	h := &ClassHierarchy{
		ByName: make(map[string]*ClassNode, len(symbols.Classes)),
	}

	// Create nodes for all classes
	for _, cls := range symbols.Classes {
		node := &ClassNode{
			Name:       cls.Name,
			File:       cls.File,
			Kind:       cls.Kind,
			Methods:    cls.Methods,
			Fields:     cls.Fields,
			HasVirtual: cls.HasVirtual,
			HasPure:    cls.HasPure,
			IsTemplate: len(cls.TemplateParams) > 0,
		}
		h.ByName[cls.Name] = node
	}

	// Wire up parent-child relationships
	for _, cls := range symbols.Classes {
		child, ok := h.ByName[cls.Name]
		if !ok {
			continue
		}

		for _, baseName := range cls.BaseClasses {
			parent, ok := h.ByName[baseName]
			if !ok {
				// Parent not found in codebase (external library base class)
				child.ParentNames = append(child.ParentNames, baseName)
				continue
			}

			child.Parents = append(child.Parents, parent)
			child.ParentNames = append(child.ParentNames, baseName)
			parent.Children = append(parent.Children, child)
			parent.ChildNames = append(parent.ChildNames, cls.Name)
		}
	}

	// Find roots (classes with no resolved parents)
	for _, node := range h.ByName {
		if len(node.Parents) == 0 {
			h.Roots = append(h.Roots, node)
		}
	}

	return h
}

// InterfaceCandidates returns classes that have at least one pure virtual method,
// making them candidates for Go interface conversion.
func (h *ClassHierarchy) InterfaceCandidates() []*ClassNode {
	var candidates []*ClassNode

	for _, node := range h.ByName {
		if node.HasPure {
			candidates = append(candidates, node)
		}
	}

	return candidates
}

// Depth returns the maximum depth of the inheritance tree from any root.
func (h *ClassHierarchy) Depth() int {
	maxDepth := 0

	for _, root := range h.Roots {
		d := treeDepth(root)
		if d > maxDepth {
			maxDepth = d
		}
	}

	return maxDepth
}

func treeDepth(node *ClassNode) int {
	if len(node.Children) == 0 {
		return 1
	}

	maxChild := 0

	for _, child := range node.Children {
		d := treeDepth(child)
		if d > maxChild {
			maxChild = d
		}
	}

	return maxChild + 1
}
