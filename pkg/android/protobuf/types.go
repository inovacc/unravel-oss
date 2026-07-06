/*
Copyright (c) 2026 Security Research
*/
package protobuf

// ScanResult holds the results of protobuf/gRPC detection in an APK.
type ScanResult struct {
	HasProtobuf    bool           `json:"has_protobuf"`
	HasGRPC        bool           `json:"has_grpc"`
	ProtoFiles     []ProtoFileRef `json:"proto_files,omitempty"`
	GRPCServices   []GRPCService  `json:"grpc_services,omitempty"`
	MessageTypes   []string       `json:"message_types,omitempty"`
	TotalProtoRefs int            `json:"total_proto_refs"`
	GRPCFramework  string         `json:"grpc_framework,omitempty"`
}

// ProtoFileRef represents a reference to a .proto file found in the APK.
type ProtoFileRef struct {
	Name   string `json:"name"`
	Source string `json:"source"` // "dex_strings" or "asset_file"
}

// GRPCService represents a detected gRPC service stub.
type GRPCService struct {
	ServiceName string `json:"service_name"`
	PackageName string `json:"package_name,omitempty"`
	ClassName   string `json:"class_name"`
	IsStub      bool   `json:"is_stub"`
	Framework   string `json:"framework,omitempty"`
}
