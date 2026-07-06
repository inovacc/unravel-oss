package jsdeob

import "fmt"

// Deobfuscate processes JavaScript code with the given options
func Deobfuscate(code string, opts Options) (*Result, error) {
	result := &Result{
		Code:            code,
		ExtractedURLs:   []string{},
		ExtractedStrs:   []string{},
		Transformations: []string{},
	}

	// Step 1: Unpack packed/encoded sections
	if opts.UnpackPacked {
		unpacked, count := UnpackPacked(result.Code)
		if count > 0 {
			result.Code = unpacked
			result.Transformations = append(result.Transformations,
				fmt.Sprintf("Unpacked %d packed sections", count))
		}
	}

	// Step 2: Decode string encodings
	if opts.DecodeStrings {
		decoded, count := DecodeStrings(result.Code)
		if count > 0 {
			result.Code = decoded
			result.Transformations = append(result.Transformations,
				fmt.Sprintf("Decoded %d encoded strings", count))
		}
	}

	// Step 3: Simplify math expressions
	if opts.SimplifyMath {
		simplified, count := SimplifyMath(result.Code)
		if count > 0 {
			result.Code = simplified
			result.Transformations = append(result.Transformations,
				fmt.Sprintf("Simplified %d constant expressions", count))
		}
	}

	// Step 4: Rename obfuscated variables
	if opts.RenameVars {
		renamed, count := RenameVariables(result.Code)
		if count > 0 {
			result.Code = renamed
			result.Transformations = append(result.Transformations,
				fmt.Sprintf("Renamed %d obfuscated variables", count))
		}
	}

	// Step 4b: Strip bundler runtime boilerplate (Phase 11 enhancement).
	// Runs BEFORE Beautify so the formatter doesn't waste passes on
	// noise that's about to be removed. Safe against semantic
	// preservation — only strips runtime plumbing that does not carry
	// export-API information (webpack `.d(...)` export tables are
	// preserved).
	if opts.StripBundlerCruft {
		stripped, count := StripBundlerBoilerplate(result.Code)
		if count > 0 {
			result.Code = stripped
			result.Transformations = append(result.Transformations,
				fmt.Sprintf("Stripped %d bundler-runtime boilerplate lines", count))
		}
	}

	// Step 5: Beautify/format code
	if opts.Beautify {
		result.Code = Beautify(result.Code)
		result.Transformations = append(result.Transformations, "Beautified code")
	}

	// Step 6: Extract strings and URLs
	if opts.ExtractStrings {
		result.ExtractedStrs = ExtractStrings(result.Code)
		result.ExtractedURLs = ExtractURLs(result.Code)
	}

	return result, nil
}
