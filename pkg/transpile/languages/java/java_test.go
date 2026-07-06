package java

import (
	"sort"
	"testing"
)

func TestDetectImports(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   []string
	}{
		{
			name:   "no imports",
			source: "public class Foo {}",
			want:   nil,
		},
		{
			name: "spring imports",
			source: `import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RestController;`,
			want: []string{"spring"},
		},
		{
			name: "multiple frameworks",
			source: `import org.springframework.web.bind.annotation.GetMapping;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;`,
			want: []string{"jackson", "junit", "slf4j", "spring"},
		},
		{
			name: "jpa imports",
			source: `import javax.persistence.Entity;
import javax.persistence.Id;`,
			want: []string{"jpa"},
		},
		{
			name:   "jakarta jpa",
			source: `import jakarta.persistence.Entity;`,
			want:   []string{"jpa"},
		},
		{
			name: "kafka imports",
			source: `import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.clients.producer.KafkaProducer;`,
			want: []string{"kafka"},
		},
		{
			name: "guava and commons",
			source: `import com.google.common.collect.ImmutableList;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.io.FileUtils;`,
			want: []string{"commons_io", "commons_lang", "guava"},
		},
		{
			name:   "static import",
			source: `import static org.junit.jupiter.api.Assertions.assertEquals;`,
			want:   []string{"junit"},
		},
		{
			name:   "wildcard import",
			source: `import org.mockito.*;`,
			want:   []string{"mockito"},
		},
		{
			name: "standard library only",
			source: `import java.util.List;
import java.util.Map;
import java.io.IOException;`,
			want: nil,
		},
	}

	l := New()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := l.DetectImports(tt.source)
			sort.Strings(got)

			if len(got) != len(tt.want) {
				t.Errorf("DetectImports() = %v, want %v", got, tt.want)
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("DetectImports()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestName(t *testing.T) {
	l := New()
	if l.Name() != "Java" {
		t.Errorf("Name() = %q, want %q", l.Name(), "Java")
	}
}

func TestExtensions(t *testing.T) {
	l := New()

	exts := l.Extensions()
	if len(exts) != 1 || exts[0] != ".java" {
		t.Errorf("Extensions() = %v, want [.java]", exts)
	}
}

func TestSystemPrompt(t *testing.T) {
	l := New()
	prompt := l.SystemPrompt()

	if prompt == "" {
		t.Error("SystemPrompt() returned empty string")
	}

	// Verify key content
	checks := []string{
		"Java-to-Go",
		"ArrayList<T>",
		"HashMap<K,V>",
		"CompletableFuture",
		"synchronized",
		"Spring Boot",
		"JUnit",
		"Lombok",
	}

	for _, check := range checks {
		if !contains(prompt, check) {
			t.Errorf("SystemPrompt() missing %q", check)
		}
	}
}

func TestConvertRawPrompt(t *testing.T) {
	l := New()
	prompt := l.ConvertRawPrompt("Foo.java", "public class Foo {}")

	if !contains(prompt, "Foo.java") {
		t.Error("ConvertRawPrompt() missing filename")
	}

	if !contains(prompt, "public class Foo {}") {
		t.Error("ConvertRawPrompt() missing source")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}

	return false
}
