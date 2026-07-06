package analysis

import "slices"

// PythonClassHierarchy represents the inheritance tree of all Python classes.
type PythonClassHierarchy struct {
	Roots  []*PythonClassNode          `json:"roots"`   // classes with no parents in codebase
	ByName map[string]*PythonClassNode `json:"by_name"` // all classes indexed by name
}

// PythonClassNode represents a class in the inheritance hierarchy.
type PythonClassNode struct {
	Name        string             `json:"name"`
	File        string             `json:"file"`
	Parents     []*PythonClassNode `json:"-"` // avoid circular JSON
	ParentNames []string           `json:"parents,omitempty"`
	Children    []*PythonClassNode `json:"-"`
	ChildNames  []string           `json:"children,omitempty"`
	Methods     []string           `json:"methods,omitempty"`
	Decorators  []string           `json:"decorators,omitempty"`
	IsAbstract  bool               `json:"is_abstract,omitempty"`
}

// BuildPythonHierarchy constructs a class inheritance tree from the Python symbol table.
func BuildPythonHierarchy(symbols *PythonSymbolTable) *PythonClassHierarchy {
	h := &PythonClassHierarchy{
		ByName: make(map[string]*PythonClassNode, len(symbols.Classes)),
	}

	// Create nodes for all classes
	for _, cls := range symbols.Classes {
		node := &PythonClassNode{
			Name:       cls.Name,
			File:       cls.File,
			Methods:    cls.Methods,
			Decorators: cls.Decorators,
			IsAbstract: cls.IsAbstract,
		}
		h.ByName[cls.Name] = node
	}

	// Wire up parent-child relationships
	for _, cls := range symbols.Classes {
		child, ok := h.ByName[cls.Name]
		if !ok {
			continue
		}

		for _, baseName := range cls.Bases {
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

// InterfaceCandidates returns classes that are abstract (ABC or Protocol),
// making them candidates for Go interface conversion.
func (h *PythonClassHierarchy) InterfaceCandidates() []*PythonClassNode {
	var candidates []*PythonClassNode

	for _, node := range h.ByName {
		if node.IsAbstract || hasProtocolBase(node) {
			candidates = append(candidates, node)
		}
	}

	return candidates
}

// Depth returns the maximum depth of the inheritance tree from any root.
func (h *PythonClassHierarchy) Depth() int {
	maxDepth := 0

	for _, root := range h.Roots {
		d := pyTreeDepth(root)
		if d > maxDepth {
			maxDepth = d
		}
	}

	return maxDepth
}

func pyTreeDepth(node *PythonClassNode) int {
	if len(node.Children) == 0 {
		return 1
	}

	maxChild := 0

	for _, child := range node.Children {
		d := pyTreeDepth(child)
		if d > maxChild {
			maxChild = d
		}
	}

	return maxChild + 1
}

// hasProtocolBase checks if a class inherits from Protocol (typing.Protocol).
func hasProtocolBase(node *PythonClassNode) bool {
	return slices.Contains(node.ParentNames, "Protocol")
}
