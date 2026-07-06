/*
Copyright (c) 2026 Security Research
*/

package kotlin

type ScanResult struct {
	HasKotlin     bool               `json:"has_kotlin"`
	KotlinVersion string             `json:"kotlin_version,omitempty"`
	Features      []FeatureInfo      `json:"features"`
	DataClasses   []DataClassInfo    `json:"data_classes,omitempty"`
	Coroutines    *CoroutineInfo     `json:"coroutines,omitempty"`
	Serialization *SerializationInfo `json:"serialization,omitempty"`
	Compose       *ComposeInfo       `json:"compose,omitempty"`
	Stats         KotlinStats        `json:"stats"`
}

type FeatureInfo struct {
	Name     string `json:"name"`
	Detected bool   `json:"detected"`
	Evidence string `json:"evidence,omitempty"`
}

type DataClassInfo struct {
	ClassName  string   `json:"class_name"`
	Properties []string `json:"properties,omitempty"`
}

type CoroutineInfo struct {
	HasCoroutines bool     `json:"has_coroutines"`
	HasFlow       bool     `json:"has_flow"`
	HasChannel    bool     `json:"has_channel"`
	Dispatchers   []string `json:"dispatchers,omitempty"`
	SuspendFuncs  int      `json:"suspend_functions"`
	Evidence      []string `json:"evidence,omitempty"`
}

type SerializationInfo struct {
	HasSerialization bool     `json:"has_serialization"`
	Format           string   `json:"format,omitempty"`
	Evidence         []string `json:"evidence,omitempty"`
}

type ComposeInfo struct {
	HasCompose  bool     `json:"has_compose"`
	Composables int      `json:"composable_count"`
	Evidence    []string `json:"evidence,omitempty"`
}

type KotlinStats struct {
	KotlinClasses    int     `json:"kotlin_classes"`
	TotalClasses     int     `json:"total_classes"`
	KotlinPercent    float64 `json:"kotlin_percent"`
	CompanionObjects int     `json:"companion_objects"`
	ObjectDecls      int     `json:"object_declarations"`
	SealedClasses    int     `json:"sealed_classes"`
	InlineClasses    int     `json:"inline_classes"`
}
