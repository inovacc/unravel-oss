package parser

import (
	"strings"

	"github.com/antlr4-go/antlr/v4"

	"github.com/inovacc/unravel-oss/pkg/transpile/languages/java/javamodel"
	"github.com/inovacc/unravel-oss/pkg/transpile/languages/java/parser/generated"
)

// visitor walks the ANTLR parse tree and builds the IR.
type visitor struct {
	generated.BaseJavaParserVisitor

	tokens antlr.TokenStream
}

func newVisitor(tokens antlr.TokenStream) *visitor {
	return &visitor{tokens: tokens}
}

func (v *visitor) visitModule(ctx generated.ICompilationUnitContext) *javamodel.Module {
	module := &javamodel.Module{}

	// Package declaration
	if pkgCtx := ctx.PackageDeclaration(); pkgCtx != nil {
		if qn := pkgCtx.QualifiedName(); qn != nil {
			module.Package = qn.GetText()
		}
	}

	// Imports
	for _, imp := range ctx.AllImportDeclaration() {
		node := v.visitImport(imp)
		if node != nil {
			module.Imports = append(module.Imports, node)
		}
	}

	// Type declarations
	for _, td := range ctx.AllTypeDeclaration() {
		nodes := v.visitTypeDeclaration(td)
		module.Types = append(module.Types, nodes...)
	}

	return module
}

func (v *visitor) visitImport(ctx generated.IImportDeclarationContext) *javamodel.Node {
	impCtx, ok := ctx.(*generated.ImportDeclarationContext)
	if !ok {
		return nil
	}

	value := ""
	if qn := impCtx.QualifiedName(); qn != nil {
		value = qn.GetText()
	}

	if impCtx.MUL() != nil {
		value += ".*"
	}

	node := &javamodel.Node{
		Type:  javamodel.NodeImport,
		Value: value,
		Line:  impCtx.GetStart().GetLine(),
	}

	if impCtx.STATIC() != nil {
		node.Metadata = map[string]string{"static": "true"}
	}

	return node
}

func (v *visitor) visitTypeDeclaration(ctx generated.ITypeDeclarationContext) []*javamodel.Node {
	tdCtx, ok := ctx.(*generated.TypeDeclarationContext)
	if !ok {
		return nil
	}

	// Extract modifiers and annotations from classOrInterfaceModifier
	var (
		modifiers   []string
		annotations []string
	)

	for _, mod := range tdCtx.AllClassOrInterfaceModifier() {
		modCtx, ok := mod.(*generated.ClassOrInterfaceModifierContext)
		if !ok {
			continue
		}

		if ann := modCtx.Annotation(); ann != nil {
			annotations = append(annotations, v.annotationText(ann))
		} else {
			modifiers = append(modifiers, modCtx.GetText())
		}
	}

	var node *javamodel.Node

	switch {
	case tdCtx.ClassDeclaration() != nil:
		node = v.visitClass(tdCtx.ClassDeclaration())
	case tdCtx.InterfaceDeclaration() != nil:
		node = v.visitInterface(tdCtx.InterfaceDeclaration())
	case tdCtx.EnumDeclaration() != nil:
		node = v.visitEnum(tdCtx.EnumDeclaration())
	case tdCtx.RecordDeclaration() != nil:
		node = v.visitRecord(tdCtx.RecordDeclaration())
	case tdCtx.AnnotationTypeDeclaration() != nil:
		node = v.visitAnnotationTypeDecl(tdCtx.AnnotationTypeDeclaration())
	default:
		return nil
	}

	if node != nil {
		node.Modifiers = modifiers
		node.Annotations = annotations
	}

	return one(node)
}

func (v *visitor) visitClass(ctx generated.IClassDeclarationContext) *javamodel.Node {
	clsCtx, ok := ctx.(*generated.ClassDeclarationContext)
	if !ok {
		return nil
	}

	node := &javamodel.Node{
		Type: javamodel.NodeClass,
		Name: identText(clsCtx.Identifier()),
		Line: clsCtx.GetStart().GetLine(),
	}

	// Extends
	if clsCtx.EXTENDS() != nil && clsCtx.TypeType() != nil {
		node.Extends = clsCtx.TypeType().GetText()
	}

	// Implements
	for _, tl := range clsCtx.AllTypeList() {
		node.Implements = append(node.Implements, typeListText(tl)...)
	}

	// Type parameters
	if tp := clsCtx.TypeParameters(); tp != nil {
		node.TypeParams = extractTypeParams(tp)
	}

	// Class body
	if body := clsCtx.ClassBody(); body != nil {
		node.Children = v.visitClassBody(body)
	}

	return node
}

func (v *visitor) visitInterface(ctx generated.IInterfaceDeclarationContext) *javamodel.Node {
	ifCtx, ok := ctx.(*generated.InterfaceDeclarationContext)
	if !ok {
		return nil
	}

	node := &javamodel.Node{
		Type: javamodel.NodeInterface,
		Name: identText(ifCtx.Identifier()),
		Line: ifCtx.GetStart().GetLine(),
	}

	// Extends (interfaces extend other interfaces)
	for _, tl := range ifCtx.AllTypeList() {
		node.Implements = append(node.Implements, typeListText(tl)...)
	}

	// Type parameters
	if tp := ifCtx.TypeParameters(); tp != nil {
		node.TypeParams = extractTypeParams(tp)
	}

	// Interface body
	if body := ifCtx.InterfaceBody(); body != nil {
		node.Children = v.visitInterfaceBody(body)
	}

	return node
}

func (v *visitor) visitEnum(ctx generated.IEnumDeclarationContext) *javamodel.Node {
	enumCtx, ok := ctx.(*generated.EnumDeclarationContext)
	if !ok {
		return nil
	}

	node := &javamodel.Node{
		Type: javamodel.NodeEnum,
		Name: identText(enumCtx.Identifier()),
		Line: enumCtx.GetStart().GetLine(),
	}

	// Implements
	if tl := enumCtx.TypeList(); tl != nil {
		node.Implements = typeListText(tl)
	}

	// Enum constants
	if ec := enumCtx.EnumConstants(); ec != nil {
		ecCtx, ok := ec.(*generated.EnumConstantsContext)
		if ok {
			for _, c := range ecCtx.AllEnumConstant() {
				cCtx, ok := c.(*generated.EnumConstantContext)
				if !ok {
					continue
				}

				constNode := &javamodel.Node{
					Type: javamodel.NodeField,
					Name: identText(cCtx.Identifier()),
					Line: cCtx.GetStart().GetLine(),
					Metadata: map[string]string{
						"kind": "enum_constant",
					},
				}

				for _, ann := range cCtx.AllAnnotation() {
					constNode.Annotations = append(constNode.Annotations, v.annotationText(ann))
				}

				node.Children = append(node.Children, constNode)
			}
		}
	}

	// Enum body declarations (methods, fields, etc.)
	if ebd := enumCtx.EnumBodyDeclarations(); ebd != nil {
		ebdCtx, ok := ebd.(*generated.EnumBodyDeclarationsContext)
		if ok {
			for _, cbd := range ebdCtx.AllClassBodyDeclaration() {
				node.Children = append(node.Children, v.visitClassBodyDeclaration(cbd)...)
			}
		}
	}

	return node
}

func (v *visitor) visitRecord(ctx generated.IRecordDeclarationContext) *javamodel.Node {
	recCtx, ok := ctx.(*generated.RecordDeclarationContext)
	if !ok {
		return nil
	}

	node := &javamodel.Node{
		Type: javamodel.NodeRecord,
		Name: identText(recCtx.Identifier()),
		Line: recCtx.GetStart().GetLine(),
	}

	// Type parameters
	if tp := recCtx.TypeParameters(); tp != nil {
		node.TypeParams = extractTypeParams(tp)
	}

	// Implements
	if tl := recCtx.TypeList(); tl != nil {
		node.Implements = typeListText(tl)
	}

	// Record components (as params)
	if rh := recCtx.RecordHeader(); rh != nil {
		rhCtx, ok := rh.(*generated.RecordHeaderContext)
		if ok {
			if rcl := rhCtx.RecordComponentList(); rcl != nil {
				rclCtx, ok := rcl.(*generated.RecordComponentListContext)
				if ok {
					for _, rc := range rclCtx.AllRecordComponent() {
						rcCompCtx, ok := rc.(*generated.RecordComponentContext)
						if !ok {
							continue
						}

						p := &javamodel.Param{
							Name: identText(rcCompCtx.Identifier()),
							Type: rcCompCtx.TypeType().GetText(),
						}

						if rcCompCtx.ELLIPSIS() != nil {
							p.IsVarargs = true
						}

						node.Params = append(node.Params, p)
					}
				}
			}
		}
	}

	// Record body
	if rb := recCtx.RecordBody(); rb != nil {
		rbCtx, ok := rb.(*generated.RecordBodyContext)
		if ok {
			for _, cbd := range rbCtx.AllClassBodyDeclaration() {
				node.Children = append(node.Children, v.visitClassBodyDeclaration(cbd)...)
			}
		}
	}

	return node
}

func (v *visitor) visitAnnotationTypeDecl(ctx generated.IAnnotationTypeDeclarationContext) *javamodel.Node {
	annCtx, ok := ctx.(*generated.AnnotationTypeDeclarationContext)
	if !ok {
		return nil
	}

	return &javamodel.Node{
		Type:  javamodel.NodeAnnotationDecl,
		Name:  identText(annCtx.Identifier()),
		Value: v.originalText(annCtx),
		Line:  annCtx.GetStart().GetLine(),
	}
}

func (v *visitor) visitClassBody(ctx generated.IClassBodyContext) []*javamodel.Node {
	cbCtx, ok := ctx.(*generated.ClassBodyContext)
	if !ok {
		return nil
	}

	var nodes []*javamodel.Node
	for _, cbd := range cbCtx.AllClassBodyDeclaration() {
		nodes = append(nodes, v.visitClassBodyDeclaration(cbd)...)
	}

	return nodes
}

func (v *visitor) visitClassBodyDeclaration(ctx generated.IClassBodyDeclarationContext) []*javamodel.Node {
	cbdCtx, ok := ctx.(*generated.ClassBodyDeclarationContext)
	if !ok {
		return nil
	}

	// Static/instance initializer block
	if cbdCtx.Block() != nil {
		blockNode := &javamodel.Node{
			Type:  javamodel.NodeBlock,
			Value: v.originalText(cbdCtx.Block()),
			Line:  cbdCtx.GetStart().GetLine(),
		}

		if cbdCtx.STATIC() != nil {
			blockNode.Modifiers = []string{"static"}
		}

		return one(blockNode)
	}

	// Member declaration with modifiers
	md := cbdCtx.MemberDeclaration()
	if md == nil {
		return nil
	}

	var (
		modifiers   []string
		annotations []string
	)

	for _, mod := range cbdCtx.AllModifier() {
		modCtx, ok := mod.(*generated.ModifierContext)
		if !ok {
			continue
		}

		coim := modCtx.ClassOrInterfaceModifier()
		if coim != nil {
			coimCtx, ok := coim.(*generated.ClassOrInterfaceModifierContext)
			if ok {
				if ann := coimCtx.Annotation(); ann != nil {
					annotations = append(annotations, v.annotationText(ann))
				} else {
					modifiers = append(modifiers, coimCtx.GetText())
				}
			}
		} else {
			modifiers = append(modifiers, modCtx.GetText())
		}
	}

	nodes := v.visitMemberDeclaration(md)

	for _, n := range nodes {
		if len(modifiers) > 0 && len(n.Modifiers) == 0 {
			n.Modifiers = modifiers
		}

		if len(annotations) > 0 && len(n.Annotations) == 0 {
			n.Annotations = annotations
		}
	}

	return nodes
}

func (v *visitor) visitMemberDeclaration(ctx generated.IMemberDeclarationContext) []*javamodel.Node {
	mdCtx, ok := ctx.(*generated.MemberDeclarationContext)
	if !ok {
		return nil
	}

	switch {
	case mdCtx.MethodDeclaration() != nil:
		return one(v.visitMethod(mdCtx.MethodDeclaration()))
	case mdCtx.GenericMethodDeclaration() != nil:
		return one(v.visitGenericMethod(mdCtx.GenericMethodDeclaration()))
	case mdCtx.FieldDeclaration() != nil:
		return one(v.visitField(mdCtx.FieldDeclaration()))
	case mdCtx.ConstructorDeclaration() != nil:
		return one(v.visitConstructor(mdCtx.ConstructorDeclaration()))
	case mdCtx.GenericConstructorDeclaration() != nil:
		return one(v.visitGenericConstructor(mdCtx.GenericConstructorDeclaration()))
	case mdCtx.ClassDeclaration() != nil:
		node := v.visitClass(mdCtx.ClassDeclaration())
		return one(node)
	case mdCtx.InterfaceDeclaration() != nil:
		return one(v.visitInterface(mdCtx.InterfaceDeclaration()))
	case mdCtx.EnumDeclaration() != nil:
		return one(v.visitEnum(mdCtx.EnumDeclaration()))
	case mdCtx.RecordDeclaration() != nil:
		return one(v.visitRecord(mdCtx.RecordDeclaration()))
	case mdCtx.AnnotationTypeDeclaration() != nil:
		return one(v.visitAnnotationTypeDecl(mdCtx.AnnotationTypeDeclaration()))
	default:
		return nil
	}
}

func (v *visitor) visitMethod(ctx generated.IMethodDeclarationContext) *javamodel.Node {
	mCtx, ok := ctx.(*generated.MethodDeclarationContext)
	if !ok {
		return nil
	}

	node := &javamodel.Node{
		Type: javamodel.NodeMethod,
		Name: identText(mCtx.Identifier()),
		Line: mCtx.GetStart().GetLine(),
	}

	// Return type
	if rtv := mCtx.TypeTypeOrVoid(); rtv != nil {
		if node.Metadata == nil {
			node.Metadata = make(map[string]string)
		}

		node.Metadata["return_type"] = rtv.GetText()
	}

	// Parameters
	if fp := mCtx.FormalParameters(); fp != nil {
		node.Params = v.extractParams(fp)
	}

	// Throws
	if mCtx.THROWS() != nil {
		if qnl := mCtx.QualifiedNameList(); qnl != nil {
			if node.Metadata == nil {
				node.Metadata = make(map[string]string)
			}

			node.Metadata["throws"] = qnl.GetText()
		}
	}

	// Body
	if mb := mCtx.MethodBody(); mb != nil {
		mbCtx, ok := mb.(*generated.MethodBodyContext)
		if ok && mbCtx.Block() != nil {
			node.Children = v.visitBlock(mbCtx.Block())
		}
	}

	return node
}

func (v *visitor) visitGenericMethod(ctx generated.IGenericMethodDeclarationContext) *javamodel.Node {
	gmCtx, ok := ctx.(*generated.GenericMethodDeclarationContext)
	if !ok {
		return nil
	}

	node := v.visitMethod(gmCtx.MethodDeclaration())
	if node != nil && gmCtx.TypeParameters() != nil {
		node.TypeParams = extractTypeParams(gmCtx.TypeParameters())
	}

	return node
}

func (v *visitor) visitConstructor(ctx generated.IConstructorDeclarationContext) *javamodel.Node {
	cCtx, ok := ctx.(*generated.ConstructorDeclarationContext)
	if !ok {
		return nil
	}

	node := &javamodel.Node{
		Type: javamodel.NodeConstructor,
		Name: identText(cCtx.Identifier()),
		Line: cCtx.GetStart().GetLine(),
	}

	// Parameters
	if fp := cCtx.FormalParameters(); fp != nil {
		node.Params = v.extractParams(fp)
	}

	// Throws
	if cCtx.THROWS() != nil {
		if qnl := cCtx.QualifiedNameList(); qnl != nil {
			if node.Metadata == nil {
				node.Metadata = make(map[string]string)
			}

			node.Metadata["throws"] = qnl.GetText()
		}
	}

	// Body
	if b := cCtx.Block(); b != nil {
		node.Children = v.visitBlock(b)
	}

	return node
}

func (v *visitor) visitGenericConstructor(ctx generated.IGenericConstructorDeclarationContext) *javamodel.Node {
	gcCtx, ok := ctx.(*generated.GenericConstructorDeclarationContext)
	if !ok {
		return nil
	}

	node := v.visitConstructor(gcCtx.ConstructorDeclaration())
	if node != nil && gcCtx.TypeParameters() != nil {
		node.TypeParams = extractTypeParams(gcCtx.TypeParameters())
	}

	return node
}

func (v *visitor) visitField(ctx generated.IFieldDeclarationContext) *javamodel.Node {
	fCtx, ok := ctx.(*generated.FieldDeclarationContext)
	if !ok {
		return nil
	}

	node := &javamodel.Node{
		Type: javamodel.NodeField,
		Line: fCtx.GetStart().GetLine(),
	}

	// Type
	if tt := fCtx.TypeType(); tt != nil {
		if node.Metadata == nil {
			node.Metadata = make(map[string]string)
		}

		node.Metadata["field_type"] = tt.GetText()
	}

	// Variable declarators
	if vds := fCtx.VariableDeclarators(); vds != nil {
		vdsCtx, ok := vds.(*generated.VariableDeclaratorsContext)
		if ok {
			decls := vdsCtx.AllVariableDeclarator()
			if len(decls) == 1 {
				vd, ok := decls[0].(*generated.VariableDeclaratorContext)
				if ok {
					node.Name = vd.VariableDeclaratorId().GetText()
					if vi := vd.VariableInitializer(); vi != nil {
						node.Value = vi.GetText()
					}
				}
			} else {
				node.Value = v.originalText(vds)
			}
		}
	}

	return node
}

func (v *visitor) visitInterfaceBody(ctx generated.IInterfaceBodyContext) []*javamodel.Node {
	ibCtx, ok := ctx.(*generated.InterfaceBodyContext)
	if !ok {
		return nil
	}

	var nodes []*javamodel.Node

	for _, ibd := range ibCtx.AllInterfaceBodyDeclaration() {
		ibdCtx, ok := ibd.(*generated.InterfaceBodyDeclarationContext)
		if !ok {
			continue
		}

		imd := ibdCtx.InterfaceMemberDeclaration()
		if imd == nil {
			continue
		}

		var (
			modifiers   []string
			annotations []string
		)

		for _, mod := range ibdCtx.AllModifier() {
			modCtx, ok := mod.(*generated.ModifierContext)
			if !ok {
				continue
			}

			coim := modCtx.ClassOrInterfaceModifier()
			if coim != nil {
				coimCtx, ok := coim.(*generated.ClassOrInterfaceModifierContext)
				if ok {
					if ann := coimCtx.Annotation(); ann != nil {
						annotations = append(annotations, v.annotationText(ann))
					} else {
						modifiers = append(modifiers, coimCtx.GetText())
					}
				}
			} else {
				modifiers = append(modifiers, modCtx.GetText())
			}
		}

		members := v.visitInterfaceMember(imd)

		for _, m := range members {
			if len(modifiers) > 0 && len(m.Modifiers) == 0 {
				m.Modifiers = modifiers
			}

			if len(annotations) > 0 && len(m.Annotations) == 0 {
				m.Annotations = annotations
			}
		}

		nodes = append(nodes, members...)
	}

	return nodes
}

func (v *visitor) visitInterfaceMember(ctx generated.IInterfaceMemberDeclarationContext) []*javamodel.Node {
	imCtx, ok := ctx.(*generated.InterfaceMemberDeclarationContext)
	if !ok {
		return nil
	}

	switch {
	case imCtx.InterfaceMethodDeclaration() != nil:
		return one(v.visitInterfaceMethod(imCtx.InterfaceMethodDeclaration()))
	case imCtx.ConstDeclaration() != nil:
		return one(v.visitConstDeclaration(imCtx.ConstDeclaration()))
	case imCtx.ClassDeclaration() != nil:
		return one(v.visitClass(imCtx.ClassDeclaration()))
	case imCtx.InterfaceDeclaration() != nil:
		return one(v.visitInterface(imCtx.InterfaceDeclaration()))
	case imCtx.EnumDeclaration() != nil:
		return one(v.visitEnum(imCtx.EnumDeclaration()))
	case imCtx.RecordDeclaration() != nil:
		return one(v.visitRecord(imCtx.RecordDeclaration()))
	default:
		return nil
	}
}

func (v *visitor) visitInterfaceMethod(ctx generated.IInterfaceMethodDeclarationContext) *javamodel.Node {
	imCtx, ok := ctx.(*generated.InterfaceMethodDeclarationContext)
	if !ok {
		return nil
	}

	icbd := imCtx.InterfaceCommonBodyDeclaration()
	if icbd == nil {
		return nil
	}

	icbdCtx, ok := icbd.(*generated.InterfaceCommonBodyDeclarationContext)
	if !ok {
		return nil
	}

	node := &javamodel.Node{
		Type: javamodel.NodeMethod,
		Name: identText(icbdCtx.Identifier()),
		Line: icbdCtx.GetStart().GetLine(),
	}

	// Return type
	if rtv := icbdCtx.TypeTypeOrVoid(); rtv != nil {
		if node.Metadata == nil {
			node.Metadata = make(map[string]string)
		}

		node.Metadata["return_type"] = rtv.GetText()
	}

	// Parameters
	if fp := icbdCtx.FormalParameters(); fp != nil {
		node.Params = v.extractParams(fp)
	}

	// Throws
	if icbdCtx.THROWS() != nil {
		if qnl := icbdCtx.QualifiedNameList(); qnl != nil {
			if node.Metadata == nil {
				node.Metadata = make(map[string]string)
			}

			node.Metadata["throws"] = qnl.GetText()
		}
	}

	// Body (default methods have one)
	if mb := icbdCtx.MethodBody(); mb != nil {
		mbCtx, ok := mb.(*generated.MethodBodyContext)
		if ok && mbCtx.Block() != nil {
			node.Children = v.visitBlock(mbCtx.Block())
		}
	}

	// Interface method modifiers (default, static, etc.)
	var modifiers []string

	for _, imm := range imCtx.AllInterfaceMethodModifier() {
		immCtx, ok := imm.(*generated.InterfaceMethodModifierContext)
		if !ok {
			continue
		}

		if immCtx.Annotation() != nil {
			node.Annotations = append(node.Annotations, v.annotationText(immCtx.Annotation()))
		} else {
			modifiers = append(modifiers, immCtx.GetText())
		}
	}

	if len(modifiers) > 0 {
		node.Modifiers = modifiers
	}

	return node
}

func (v *visitor) visitConstDeclaration(ctx generated.IConstDeclarationContext) *javamodel.Node {
	cdCtx, ok := ctx.(*generated.ConstDeclarationContext)
	if !ok {
		return nil
	}

	return &javamodel.Node{
		Type:  javamodel.NodeField,
		Value: v.originalText(cdCtx),
		Line:  cdCtx.GetStart().GetLine(),
	}
}

// --- Statements ---

func (v *visitor) visitBlock(ctx generated.IBlockContext) []*javamodel.Node {
	bCtx, ok := ctx.(*generated.BlockContext)
	if !ok {
		return nil
	}

	var nodes []*javamodel.Node
	for _, bs := range bCtx.AllBlockStatement() {
		nodes = append(nodes, v.visitBlockStatement(bs)...)
	}

	return nodes
}

func (v *visitor) visitBlockStatement(ctx generated.IBlockStatementContext) []*javamodel.Node {
	bsCtx, ok := ctx.(*generated.BlockStatementContext)
	if !ok {
		return nil
	}

	switch {
	case bsCtx.LocalVariableDeclaration() != nil:
		return one(v.visitLocalVarDecl(bsCtx.LocalVariableDeclaration()))
	case bsCtx.Statement() != nil:
		return one(v.visitStatement(bsCtx.Statement()))
	case bsCtx.LocalTypeDeclaration() != nil:
		return one(v.visitLocalTypeDecl(bsCtx.LocalTypeDeclaration()))
	default:
		return nil
	}
}

func (v *visitor) visitLocalVarDecl(ctx generated.ILocalVariableDeclarationContext) *javamodel.Node {
	return &javamodel.Node{
		Type:  javamodel.NodeAssign,
		Value: v.originalText(ctx),
		Line:  ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitLocalTypeDecl(ctx generated.ILocalTypeDeclarationContext) *javamodel.Node {
	ltdCtx, ok := ctx.(*generated.LocalTypeDeclarationContext)
	if !ok {
		return nil
	}

	switch {
	case ltdCtx.ClassDeclaration() != nil:
		return v.visitClass(ltdCtx.ClassDeclaration())
	case ltdCtx.InterfaceDeclaration() != nil:
		return v.visitInterface(ltdCtx.InterfaceDeclaration())
	case ltdCtx.RecordDeclaration() != nil:
		return v.visitRecord(ltdCtx.RecordDeclaration())
	case ltdCtx.EnumDeclaration() != nil:
		return v.visitEnum(ltdCtx.EnumDeclaration())
	default:
		return nil
	}
}

func (v *visitor) visitStatement(ctx generated.IStatementContext) *javamodel.Node {
	sCtx, ok := ctx.(*generated.StatementContext)
	if !ok {
		return nil
	}

	switch {
	case sCtx.IF() != nil:
		return v.visitIfStmt(sCtx)
	case sCtx.FOR() != nil:
		return v.visitForStmt(sCtx)
	case sCtx.WHILE() != nil && sCtx.DO() == nil:
		return v.visitWhileStmt(sCtx)
	case sCtx.DO() != nil:
		return v.visitDoWhileStmt(sCtx)
	case sCtx.SWITCH() != nil:
		return v.visitSwitchStmt(sCtx)
	case sCtx.TRY() != nil:
		return v.visitTryStmt(sCtx)
	case sCtx.RETURN() != nil:
		return v.visitReturnStmt(sCtx)
	case sCtx.THROW() != nil:
		return v.visitThrowStmt(sCtx)
	case sCtx.BREAK() != nil:
		return &javamodel.Node{
			Type: javamodel.NodeBreak,
			Line: sCtx.GetStart().GetLine(),
		}
	case sCtx.CONTINUE() != nil:
		return &javamodel.Node{
			Type: javamodel.NodeContinue,
			Line: sCtx.GetStart().GetLine(),
		}
	case sCtx.Block() != nil:
		return &javamodel.Node{
			Type:     javamodel.NodeBlock,
			Children: v.visitBlock(sCtx.Block()),
			Line:     sCtx.GetStart().GetLine(),
		}
	default:
		// Expression statement or other
		return &javamodel.Node{
			Type:  javamodel.NodeExpr,
			Value: v.originalText(sCtx),
			Line:  sCtx.GetStart().GetLine(),
		}
	}
}

// stmtBody lowers a single Java statement into a structured child list,
// flattening a brace block into its statements.
func (v *visitor) stmtBody(ctx generated.IStatementContext) []*javamodel.Node {
	if ctx == nil {
		return nil
	}

	n := v.visitStatement(ctx)
	if n == nil {
		return nil
	}

	if n.Type == javamodel.NodeBlock {
		return n.Children
	}

	return []*javamodel.Node{n}
}

// visitIfStmt builds a structured if/else-if/else chain. Grammar:
// IF parExpression statement (ELSE statement)?. An `else if` nests as a
// single NodeIf in Orelse.
func (v *visitor) visitIfStmt(ctx *generated.StatementContext) *javamodel.Node {
	node := &javamodel.Node{
		Type: javamodel.NodeIf,
		Line: ctx.GetStart().GetLine(),
	}

	if e := ctx.Expression(0); e != nil {
		node.Cond = v.originalText(e)
	}

	if stmts := ctx.AllStatement(); len(stmts) > 0 {
		node.Children = v.stmtBody(stmts[0])

		if ctx.ELSE() != nil && len(stmts) > 1 {
			elseStmt := stmts[1]
			if es, ok := elseStmt.(*generated.StatementContext); ok && es.IF() != nil {
				node.Orelse = []*javamodel.Node{v.visitIfStmt(es)}
			} else {
				node.Orelse = v.stmtBody(elseStmt)
			}
		}
	}

	return node
}

// visitForStmt structures classic and enhanced (for-each) for loops.
func (v *visitor) visitForStmt(ctx *generated.StatementContext) *javamodel.Node {
	node := &javamodel.Node{
		Type: javamodel.NodeFor,
		Line: ctx.GetStart().GetLine(),
	}

	if fc, ok := ctx.ForControl().(*generated.ForControlContext); ok && fc != nil {
		if efc, ok := fc.EnhancedForControl().(*generated.EnhancedForControlContext); ok && efc != nil {
			node.Type = javamodel.NodeForEach

			if id := efc.VariableDeclaratorId(); id != nil {
				node.Target = v.originalText(id)
			}

			if it := efc.Expression(); it != nil {
				node.Cond = v.originalText(it)
			}
		} else {
			// Classic for: keep the full control clause for the lowerer.
			node.Value = v.originalText(fc)
		}
	}

	if stmts := ctx.AllStatement(); len(stmts) > 0 {
		node.Children = v.stmtBody(stmts[0])
	}

	return node
}

func (v *visitor) visitWhileStmt(ctx *generated.StatementContext) *javamodel.Node {
	node := &javamodel.Node{
		Type: javamodel.NodeWhile,
		Line: ctx.GetStart().GetLine(),
	}

	if e := ctx.Expression(0); e != nil {
		node.Cond = v.originalText(e)
	}

	if stmts := ctx.AllStatement(); len(stmts) > 0 {
		node.Children = v.stmtBody(stmts[0])
	}

	return node
}

func (v *visitor) visitDoWhileStmt(ctx *generated.StatementContext) *javamodel.Node {
	node := &javamodel.Node{
		Type: javamodel.NodeDoWhile,
		Line: ctx.GetStart().GetLine(),
	}

	if e := ctx.Expression(0); e != nil {
		node.Cond = v.originalText(e)
	}

	if stmts := ctx.AllStatement(); len(stmts) > 0 {
		node.Children = v.stmtBody(stmts[0])
	}

	return node
}

func (v *visitor) visitSwitchStmt(ctx *generated.StatementContext) *javamodel.Node {
	return &javamodel.Node{
		Type:  javamodel.NodeSwitch,
		Value: v.originalText(ctx),
		Line:  ctx.GetStart().GetLine(),
	}
}

func (v *visitor) visitTryStmt(ctx *generated.StatementContext) *javamodel.Node {
	node := &javamodel.Node{
		Type:  javamodel.NodeTry,
		Value: v.originalText(ctx),
		Line:  ctx.GetStart().GetLine(),
	}

	return node
}

func (v *visitor) visitReturnStmt(ctx *generated.StatementContext) *javamodel.Node {
	node := &javamodel.Node{
		Type: javamodel.NodeReturn,
		Line: ctx.GetStart().GetLine(),
	}

	exprs := ctx.AllExpression()
	if len(exprs) > 0 {
		node.Value = v.originalText(exprs[0])
	}

	return node
}

func (v *visitor) visitThrowStmt(ctx *generated.StatementContext) *javamodel.Node {
	node := &javamodel.Node{
		Type: javamodel.NodeThrow,
		Line: ctx.GetStart().GetLine(),
	}

	exprs := ctx.AllExpression()
	if len(exprs) > 0 {
		node.Value = v.originalText(exprs[0])
	}

	return node
}

// --- Parameters ---

func (v *visitor) extractParams(ctx generated.IFormalParametersContext) []*javamodel.Param {
	fpCtx, ok := ctx.(*generated.FormalParametersContext)
	if !ok {
		return nil
	}

	var params []*javamodel.Param

	// Direct formalParameter
	if fp := fpCtx.FormalParameter(); fp != nil {
		params = append(params, v.extractParam(fp))
	}

	// FormalParameterList(s)
	for _, fpl := range fpCtx.AllFormalParameterList() {
		fplCtx, ok := fpl.(*generated.FormalParameterListContext)
		if !ok {
			continue
		}

		for _, fp := range fplCtx.AllFormalParameter() {
			params = append(params, v.extractParam(fp))
		}
	}

	return params
}

func (v *visitor) extractParam(ctx generated.IFormalParameterContext) *javamodel.Param {
	fpCtx, ok := ctx.(*generated.FormalParameterContext)
	if !ok {
		return &javamodel.Param{Name: "?"}
	}

	p := &javamodel.Param{}

	if tt := fpCtx.TypeType(); tt != nil {
		p.Type = tt.GetText()
	}

	if vid := fpCtx.VariableDeclaratorId(); vid != nil {
		p.Name = vid.GetText()
	}

	if fpCtx.ELLIPSIS() != nil {
		p.IsVarargs = true
	}

	// Variable modifiers
	for _, vm := range fpCtx.AllVariableModifier() {
		vmCtx, ok := vm.(*generated.VariableModifierContext)
		if !ok {
			continue
		}

		if vmCtx.FINAL() != nil {
			p.Modifiers = append(p.Modifiers, "final")
		}

		if ann := vmCtx.Annotation(); ann != nil {
			p.Annotations = append(p.Annotations, v.annotationText(ann))
		}
	}

	return p
}

// --- Helpers ---

func (v *visitor) annotationText(ctx generated.IAnnotationContext) string {
	annCtx, ok := ctx.(*generated.AnnotationContext)
	if !ok {
		return ""
	}

	if qn := annCtx.QualifiedName(); qn != nil {
		return "@" + qn.GetText()
	}

	return ""
}

func (v *visitor) originalText(ctx antlr.ParserRuleContext) string {
	if ctx == nil || ctx.GetStart() == nil || ctx.GetStop() == nil {
		return ""
	}

	start := ctx.GetStart().GetTokenIndex()
	stop := ctx.GetStop().GetTokenIndex()

	if start < 0 || stop < 0 || start > stop {
		return ctx.GetText()
	}

	var sb strings.Builder

	for i := start; i <= stop; i++ {
		tok := v.tokens.Get(i)
		sb.WriteString(tok.GetText())
	}

	return sb.String()
}

func identText(ctx generated.IIdentifierContext) string {
	if ctx == nil {
		return ""
	}

	return ctx.GetText()
}

func extractTypeParams(ctx generated.ITypeParametersContext) []string {
	tpCtx, ok := ctx.(*generated.TypeParametersContext)
	if !ok {
		return nil
	}

	var params []string
	for _, tp := range tpCtx.AllTypeParameter() {
		params = append(params, tp.GetText())
	}

	return params
}

func typeListText(ctx generated.ITypeListContext) []string {
	tlCtx, ok := ctx.(*generated.TypeListContext)
	if !ok {
		return nil
	}

	var types []string
	for _, tt := range tlCtx.AllTypeType() {
		types = append(types, tt.GetText())
	}

	return types
}

func one(n *javamodel.Node) []*javamodel.Node {
	if n == nil {
		return nil
	}

	return []*javamodel.Node{n}
}
