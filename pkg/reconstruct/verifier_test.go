package reconstruct

import (
	"strings"
	"testing"
)

func TestVerifySyntaxValidBalancedBraces(t *testing.T) {
	original := `public class Foo {
    public void bar() {
        System.out.println("hello");
    }
}`
	reconstructed := `public class Foo {
    public void bar() {
        System.out.println("hello world");
    }
}`
	result := Verify(original, reconstructed, LangJava)
	if !result.SyntaxValid {
		t.Error("expected SyntaxValid=true for balanced braces")
	}
}

func TestVerifySyntaxInvalidUnbalancedBraces(t *testing.T) {
	original := `public class Foo {
    public void bar() {
        System.out.println("hello");
    }
}`
	reconstructed := `public class Foo {
    public void bar() {
        System.out.println("hello");
    // missing closing brace`
	result := Verify(original, reconstructed, LangJava)
	if result.SyntaxValid {
		t.Error("expected SyntaxValid=false for unbalanced braces")
	}
}

func TestVerifySymbolsPreservedAllPresent(t *testing.T) {
	original := `public class Foo {
    public void doStuff() {}
    public int getValue() { return 0; }
}`
	reconstructed := `public class Foo {
    public void doStuff() {
        // improved
    }
    public int getValue() { return 42; }
}`
	result := Verify(original, reconstructed, LangJava)
	if !result.SymbolsPreserved {
		t.Error("expected SymbolsPreserved=true when all symbols present")
	}
}

func TestVerifySymbolsMissing(t *testing.T) {
	original := `public class Foo {
    public void doStuff() {}
    public int getValue() { return 0; }
}`
	reconstructed := `public class Foo {
    public void doStuff() {
        // improved
    }
}`
	result := Verify(original, reconstructed, LangJava)
	if result.SymbolsPreserved {
		t.Error("expected SymbolsPreserved=false when symbol missing")
	}
}

func TestVerifyASTSimilarityHighForSameStructure(t *testing.T) {
	original := `public class Foo {
    public void bar() {
        if (x > 0) {
            for (int i = 0; i < n; i++) {
                doSomething();
            }
        }
        return result;
    }
}`
	// Same structure, different variable names
	reconstructed := `public class Foo {
    public void bar() {
        if (y > 0) {
            for (int j = 0; j < count; j++) {
                doAction();
            }
        }
        return output;
    }
}`
	result := Verify(original, reconstructed, LangJava)
	if result.ASTSimilarity <= 0.8 {
		t.Errorf("expected ASTSimilarity > 0.8, got %f", result.ASTSimilarity)
	}
}

func TestVerifyASTSimilarityLowForDifferentCode(t *testing.T) {
	original := `public class Foo {
    public void bar() {
        if (x > 0) {
            for (int i = 0; i < n; i++) {
                doSomething();
            }
        }
        return result;
    }
}`
	reconstructed := `x = 1
y = 2
z = x + y
print(z)`
	result := Verify(original, reconstructed, LangJava)
	if result.ASTSimilarity >= 0.4 {
		t.Errorf("expected ASTSimilarity < 0.4, got %f", result.ASTSimilarity)
	}
}

func TestVerifyLineDeltaFlags(t *testing.T) {
	original := strings.Repeat("line\n", 10)
	// 16 lines = 60% growth > 50% threshold
	reconstructed := strings.Repeat("line\n", 16)
	result := Verify(original, reconstructed, LangUnknown)
	if result.LineDelta <= 0.5 {
		t.Errorf("expected LineDelta > 0.5, got %f", result.LineDelta)
	}
}

func TestVerifyAllChecksPassed(t *testing.T) {
	original := `public class Foo {
    public void bar() {
        if (x > 0) {
            doSomething();
        }
    }
}`
	reconstructed := `public class Foo {
    public void bar() {
        if (y > 0) {
            doAction();
        }
    }
}`
	result := Verify(original, reconstructed, LangJava)
	if !result.Passed {
		t.Errorf("expected Passed=true, failures: %v", result.Failures)
	}
}

func TestVerifySyntaxFailureNotRetryable(t *testing.T) {
	original := `public class Foo { public void bar() {} }`
	reconstructed := `public class Foo { public void bar() {`
	result := Verify(original, reconstructed, LangJava)
	if result.Passed {
		t.Error("expected Passed=false for syntax failure")
	}
	if result.RetryRecommended {
		t.Error("expected RetryRecommended=false for syntax failure")
	}
}

func TestVerifySymbolFailureRetryable(t *testing.T) {
	original := `public class Foo {
    public void importantMethod() {}
    public void secondaryMethod() {}
}`
	reconstructed := `public class Foo {
    public void importantMethod() {
        // enhanced
    }
}`
	result := Verify(original, reconstructed, LangJava)
	if result.Passed {
		t.Error("expected Passed=false for symbol failure")
	}
	if !result.RetryRecommended {
		t.Error("expected RetryRecommended=true for non-syntax failure")
	}
}

func TestVerifyGoSyntaxWithParser(t *testing.T) {
	original := `package main

func Hello() string {
	return "hello"
}
`
	reconstructed := `package main

func Hello() string {
	return "world"
}
`
	result := Verify(original, reconstructed, LangGo)
	if !result.SyntaxValid {
		t.Error("expected SyntaxValid=true for valid Go code")
	}
	if !result.Passed {
		t.Errorf("expected Passed=true, failures: %v", result.Failures)
	}
}

func TestVerifyGoSyntaxInvalid(t *testing.T) {
	original := `package main

func Hello() string {
	return "hello"
}
`
	reconstructed := `package main

func Hello() string {
	return "world"
// missing closing brace`
	result := Verify(original, reconstructed, LangGo)
	if result.SyntaxValid {
		t.Error("expected SyntaxValid=false for invalid Go code")
	}
}
