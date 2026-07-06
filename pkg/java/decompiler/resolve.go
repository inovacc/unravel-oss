package decompiler

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/constantpool"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/pipeline"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// cpResolver adapts constantpool.Pool to the pipeline.CPResolver interface.
type cpResolver struct {
	pool *constantpool.Pool
}

// newCPResolver wraps a constant pool as a pipeline CPResolver.
func newCPResolver(pool *constantpool.Pool) pipeline.CPResolver {
	return &cpResolver{pool: pool}
}

func (r *cpResolver) ResolveClass(index uint16) (types.JavaType, error) {
	name := r.pool.ClassName(index)
	if name == "" {
		return nil, fmt.Errorf("unresolved class at cp#%d", index)
	}

	return types.NewRefTypeFromInternal(name), nil
}

func (r *cpResolver) ResolveFieldRef(index uint16) (*ast.FieldRef, error) {
	className, fieldName, fieldDesc := r.pool.FieldRefInfo(index)
	if className == "" {
		return nil, fmt.Errorf("unresolved field ref at cp#%d", index)
	}

	fieldType, err := types.ParseFieldDescriptor(fieldDesc)
	if err != nil {
		return nil, fmt.Errorf("parse field descriptor %q: %w", fieldDesc, err)
	}

	return &ast.FieldRef{
		ClassName:  strings.ReplaceAll(className, "/", "."),
		FieldName:  fieldName,
		Descriptor: fieldDesc,
		FieldType:  fieldType,
	}, nil
}

func (r *cpResolver) resolveMethodRef(index uint16) (*ast.MethodRef, error) {
	className, methodName, methodDesc := r.pool.MethodRefInfo(index)
	if className == "" {
		return nil, fmt.Errorf("unresolved method ref at cp#%d", index)
	}

	params, retType, err := types.ParseMethodDescriptor(methodDesc)
	if err != nil {
		return nil, fmt.Errorf("parse method descriptor %q: %w", methodDesc, err)
	}

	return &ast.MethodRef{
		ClassName:  strings.ReplaceAll(className, "/", "."),
		MethodName: methodName,
		Descriptor: methodDesc,
		ParamTypes: params,
		ReturnType: retType,
	}, nil
}

func (r *cpResolver) ResolveMethodRef(index uint16) (*ast.MethodRef, error) {
	return r.resolveMethodRef(index)
}

func (r *cpResolver) ResolveInterfaceMethodRef(index uint16) (*ast.MethodRef, error) {
	return r.resolveMethodRef(index)
}

func (r *cpResolver) ResolveLiteral(index uint16) (*ast.Literal, error) {
	e := r.pool.Get(index)
	if e == nil {
		return nil, fmt.Errorf("unresolved literal at cp#%d", index)
	}

	switch e.Tag {
	case constantpool.TagInteger:
		return ast.NewIntLiteral(e.IntValue), nil
	case constantpool.TagFloat:
		return ast.NewFloatLiteral(e.FloatValue), nil
	case constantpool.TagLong:
		return ast.NewLongLiteral(e.LongValue), nil
	case constantpool.TagDouble:
		return ast.NewDoubleLiteral(e.DoubleValue), nil
	case constantpool.TagString:
		return ast.NewStringLiteral(r.pool.StringValue(index)), nil
	case constantpool.TagClass:
		name := r.pool.ClassName(index)
		return ast.NewClassLiteral(types.NewRefTypeFromInternal(name)), nil
	default:
		return nil, fmt.Errorf("unexpected literal tag %s at cp#%d", e.Tag, index)
	}
}

func (r *cpResolver) ResolveInvokeDynamic(index uint16) (*ast.DynamicInvocation, error) {
	e := r.pool.Get(index)
	if e == nil {
		return nil, fmt.Errorf("unresolved invokedynamic at cp#%d", index)
	}

	if e.Tag != constantpool.TagInvokeDynamic {
		return nil, fmt.Errorf("expected InvokeDynamic at cp#%d, got %s", index, e.Tag)
	}

	name, desc := r.pool.NameAndType(e.NameAndTypeIndex)

	_, retType, err := types.ParseMethodDescriptor(desc)
	if err != nil {
		retType = types.TypeRef
	}

	return ast.NewDynamicInvocation(
		int(e.BootstrapMethodAttrIndex),
		name,
		desc,
		nil, // args are resolved by the stack simulation
		retType,
	), nil
}

func (r *cpResolver) ResolveNameAndType(index uint16) (string, string, error) {
	name, desc := r.pool.NameAndType(index)
	if name == "" && desc == "" {
		return "", "", fmt.Errorf("unresolved name-and-type at cp#%d", index)
	}

	return name, desc, nil
}
