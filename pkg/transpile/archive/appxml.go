package archive

import (
	"encoding/xml"
)

// AppXMLInfo holds parsed data from META-INF/application.xml (EAR descriptor).
type AppXMLInfo struct {
	Modules       []*EARModule    `json:"modules,omitempty"`
	SecurityRoles []*SecurityRole `json:"security_roles,omitempty"`
}

// EARModule describes a module within an EAR archive.
type EARModule struct {
	Type        string `json:"type"` // "web", "ejb", "java", "connector"
	URI         string `json:"uri"`
	ContextRoot string `json:"context_root,omitempty"` // for web modules only
}

// SecurityRole describes a security role in an EAR.
type SecurityRole struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// xmlApplication is the internal XML representation for application.xml.
type xmlApplication struct {
	XMLName       xml.Name          `xml:"application"`
	Modules       []xmlModule       `xml:"module"`
	SecurityRoles []xmlSecurityRole `xml:"security-role"`
}

type xmlModule struct {
	Web       *xmlWebModule `xml:"web"`
	EJB       string        `xml:"ejb"`
	Java      string        `xml:"java"`
	Connector string        `xml:"connector"`
}

type xmlWebModule struct {
	WebURI      string `xml:"web-uri"`
	ContextRoot string `xml:"context-root"`
}

type xmlSecurityRole struct {
	RoleName    string `xml:"role-name"`
	Description string `xml:"description"`
}

// ParseAppXML parses a META-INF/application.xml file.
func ParseAppXML(data []byte) (*AppXMLInfo, error) {
	var app xmlApplication
	if err := xml.Unmarshal(data, &app); err != nil {
		return nil, err
	}

	info := &AppXMLInfo{}

	for _, m := range app.Modules {
		switch {
		case m.Web != nil:
			info.Modules = append(info.Modules, &EARModule{
				Type:        "web",
				URI:         m.Web.WebURI,
				ContextRoot: m.Web.ContextRoot,
			})
		case m.EJB != "":
			info.Modules = append(info.Modules, &EARModule{
				Type: "ejb",
				URI:  m.EJB,
			})
		case m.Java != "":
			info.Modules = append(info.Modules, &EARModule{
				Type: "java",
				URI:  m.Java,
			})
		case m.Connector != "":
			info.Modules = append(info.Modules, &EARModule{
				Type: "connector",
				URI:  m.Connector,
			})
		}
	}

	for _, r := range app.SecurityRoles {
		info.SecurityRoles = append(info.SecurityRoles, &SecurityRole{
			Name:        r.RoleName,
			Description: r.Description,
		})
	}

	return info, nil
}
