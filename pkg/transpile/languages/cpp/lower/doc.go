// Package lower transforms a C++ semantic AST ([ast.TranslationUnit]) into
// the language-agnostic intermediate representation ([ir.Module]). It maps
// C++ types to IR equivalents (std::vector → slice, std::map → map, etc.),
// converts constructors to factory functions, destructors to Close methods,
// and virtual methods to interface declarations.
package lower
