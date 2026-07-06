package archive

import (
	"encoding/xml"
)

// POMInfo holds parsed data from pom.xml.
type POMInfo struct {
	GroupID      string            `json:"group_id,omitempty"`
	ArtifactID   string            `json:"artifact_id,omitempty"`
	Version      string            `json:"version,omitempty"`
	Packaging    string            `json:"packaging,omitempty"`
	Dependencies []*Dependency     `json:"dependencies,omitempty"`
	Plugins      []*Plugin         `json:"plugins,omitempty"`
	Properties   map[string]string `json:"properties,omitempty"`
}

// Dependency describes a Maven dependency.
type Dependency struct {
	GroupID    string `json:"group_id" xml:"groupId"`
	ArtifactID string `json:"artifact_id" xml:"artifactId"`
	Version    string `json:"version,omitempty" xml:"version"`
	Scope      string `json:"scope,omitempty" xml:"scope"`
}

// Plugin describes a Maven build plugin.
type Plugin struct {
	GroupID    string `json:"group_id" xml:"groupId"`
	ArtifactID string `json:"artifact_id" xml:"artifactId"`
	Version    string `json:"version,omitempty" xml:"version"`
}

// xmlProject is the internal XML representation for pom.xml.
type xmlProject struct {
	XMLName      xml.Name        `xml:"project"`
	GroupID      string          `xml:"groupId"`
	ArtifactID   string          `xml:"artifactId"`
	Version      string          `xml:"version"`
	Packaging    string          `xml:"packaging"`
	Dependencies xmlDependencies `xml:"dependencies"`
	Build        xmlBuild        `xml:"build"`
	Properties   xmlProperties   `xml:"properties"`
	Parent       xmlParent       `xml:"parent"`
}

type xmlDependencies struct {
	Deps []xmlDependency `xml:"dependency"`
}

type xmlDependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type xmlBuild struct {
	Plugins xmlPlugins `xml:"plugins"`
}

type xmlPlugins struct {
	Plugins []xmlPlugin `xml:"plugin"`
}

type xmlPlugin struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type xmlProperties struct {
	Items []xmlProperty `xml:",any"`
}

type xmlProperty struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type xmlParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// ParsePOM parses a pom.xml file.
func ParsePOM(data []byte) (*POMInfo, error) {
	var project xmlProject
	if err := xml.Unmarshal(data, &project); err != nil {
		return nil, err
	}

	info := &POMInfo{
		GroupID:    project.GroupID,
		ArtifactID: project.ArtifactID,
		Version:    project.Version,
		Packaging:  project.Packaging,
		Properties: make(map[string]string),
	}

	// Inherit from parent if not set
	if info.GroupID == "" && project.Parent.GroupID != "" {
		info.GroupID = project.Parent.GroupID
	}

	if info.Version == "" && project.Parent.Version != "" {
		info.Version = project.Parent.Version
	}

	// Dependencies
	for _, d := range project.Dependencies.Deps {
		info.Dependencies = append(info.Dependencies, &Dependency{
			GroupID:    d.GroupID,
			ArtifactID: d.ArtifactID,
			Version:    d.Version,
			Scope:      d.Scope,
		})
	}

	// Plugins
	for _, p := range project.Build.Plugins.Plugins {
		info.Plugins = append(info.Plugins, &Plugin{
			GroupID:    p.GroupID,
			ArtifactID: p.ArtifactID,
			Version:    p.Version,
		})
	}

	// Properties
	for _, prop := range project.Properties.Items {
		info.Properties[prop.XMLName.Local] = prop.Value
	}

	return info, nil
}
