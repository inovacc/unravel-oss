package archive

import (
	"encoding/xml"
)

// WebXMLInfo holds parsed data from WEB-INF/web.xml.
type WebXMLInfo struct {
	Servlets            []*ServletInfo        `json:"servlets,omitempty"`
	ServletMappings     []*ServletMapping     `json:"servlet_mappings,omitempty"`
	Filters             []*FilterInfo         `json:"filters,omitempty"`
	FilterMappings      []*FilterMapping      `json:"filter_mappings,omitempty"`
	Listeners           []*ListenerInfo       `json:"listeners,omitempty"`
	ContextParams       map[string]string     `json:"context_params,omitempty"`
	ErrorPages          []*ErrorPage          `json:"error_pages,omitempty"`
	WelcomeFiles        []string              `json:"welcome_files,omitempty"`
	SecurityConstraints []*SecurityConstraint `json:"security_constraints,omitempty"`
}

// ServletInfo describes a servlet declaration.
type ServletInfo struct {
	Name          string            `json:"name" xml:"servlet-name"`
	Class         string            `json:"class" xml:"servlet-class"`
	InitParams    map[string]string `json:"init_params,omitempty"`
	LoadOnStartup int               `json:"load_on_startup,omitempty" xml:"load-on-startup"`
}

// ServletMapping maps a servlet name to URL patterns.
type ServletMapping struct {
	ServletName string `json:"servlet_name" xml:"servlet-name"`
	URLPattern  string `json:"url_pattern" xml:"url-pattern"`
}

// FilterInfo describes a filter declaration.
type FilterInfo struct {
	Name  string `json:"name" xml:"filter-name"`
	Class string `json:"class" xml:"filter-class"`
}

// FilterMapping maps a filter name to URL patterns.
type FilterMapping struct {
	FilterName string `json:"filter_name" xml:"filter-name"`
	URLPattern string `json:"url_pattern" xml:"url-pattern"`
}

// ListenerInfo describes a listener.
type ListenerInfo struct {
	Class string `json:"class" xml:"listener-class"`
}

// ErrorPage maps an error code or exception to a location.
type ErrorPage struct {
	ErrorCode     int    `json:"error_code,omitempty" xml:"error-code"`
	ExceptionType string `json:"exception_type,omitempty" xml:"exception-type"`
	Location      string `json:"location" xml:"location"`
}

// SecurityConstraint describes a security constraint.
type SecurityConstraint struct {
	WebResourceName string   `json:"web_resource_name,omitempty"`
	URLPatterns     []string `json:"url_patterns,omitempty"`
	HTTPMethods     []string `json:"http_methods,omitempty"`
	AuthRoles       []string `json:"auth_roles,omitempty"`
}

// xmlWebApp is the internal representation for unmarshaling web.xml.
type xmlWebApp struct {
	XMLName         xml.Name            `xml:"web-app"`
	Servlets        []xmlServlet        `xml:"servlet"`
	ServletMappings []xmlServletMapping `xml:"servlet-mapping"`
	Filters         []xmlFilter         `xml:"filter"`
	FilterMappings  []xmlFilterMapping  `xml:"filter-mapping"`
	Listeners       []xmlListener       `xml:"listener"`
	ContextParams   []xmlContextParam   `xml:"context-param"`
	ErrorPages      []xmlErrorPage      `xml:"error-page"`
	WelcomeFiles    xmlWelcomeFileList  `xml:"welcome-file-list"`
	SecurityConstr  []xmlSecurityConstr `xml:"security-constraint"`
}

type xmlServlet struct {
	Name          string         `xml:"servlet-name"`
	Class         string         `xml:"servlet-class"`
	InitParams    []xmlInitParam `xml:"init-param"`
	LoadOnStartup int            `xml:"load-on-startup"`
}

type xmlInitParam struct {
	Name  string `xml:"param-name"`
	Value string `xml:"param-value"`
}

type xmlServletMapping struct {
	Name       string `xml:"servlet-name"`
	URLPattern string `xml:"url-pattern"`
}

type xmlFilter struct {
	Name  string `xml:"filter-name"`
	Class string `xml:"filter-class"`
}

type xmlFilterMapping struct {
	Name       string `xml:"filter-name"`
	URLPattern string `xml:"url-pattern"`
}

type xmlListener struct {
	Class string `xml:"listener-class"`
}

type xmlContextParam struct {
	Name  string `xml:"param-name"`
	Value string `xml:"param-value"`
}

type xmlErrorPage struct {
	ErrorCode     int    `xml:"error-code"`
	ExceptionType string `xml:"exception-type"`
	Location      string `xml:"location"`
}

type xmlWelcomeFileList struct {
	Files []string `xml:"welcome-file"`
}

type xmlSecurityConstr struct {
	WebResourceCollection xmlWebResourceCollection `xml:"web-resource-collection"`
	AuthConstraint        xmlAuthConstraint        `xml:"auth-constraint"`
}

type xmlWebResourceCollection struct {
	Name        string   `xml:"web-resource-name"`
	URLPatterns []string `xml:"url-pattern"`
	HTTPMethods []string `xml:"http-method"`
}

type xmlAuthConstraint struct {
	Roles []string `xml:"role-name"`
}

// ParseWebXML parses a web.xml file.
func ParseWebXML(data []byte) (*WebXMLInfo, error) {
	var app xmlWebApp
	if err := xml.Unmarshal(data, &app); err != nil {
		return nil, err
	}

	info := &WebXMLInfo{
		ContextParams: make(map[string]string),
	}

	// Servlets
	for _, s := range app.Servlets {
		servlet := &ServletInfo{
			Name:          s.Name,
			Class:         s.Class,
			LoadOnStartup: s.LoadOnStartup,
		}
		if len(s.InitParams) > 0 {
			servlet.InitParams = make(map[string]string, len(s.InitParams))
			for _, p := range s.InitParams {
				servlet.InitParams[p.Name] = p.Value
			}
		}

		info.Servlets = append(info.Servlets, servlet)
	}

	// Servlet mappings
	for _, m := range app.ServletMappings {
		info.ServletMappings = append(info.ServletMappings, &ServletMapping{
			ServletName: m.Name,
			URLPattern:  m.URLPattern,
		})
	}

	// Filters
	for _, f := range app.Filters {
		info.Filters = append(info.Filters, &FilterInfo{
			Name:  f.Name,
			Class: f.Class,
		})
	}

	// Filter mappings
	for _, m := range app.FilterMappings {
		info.FilterMappings = append(info.FilterMappings, &FilterMapping{
			FilterName: m.Name,
			URLPattern: m.URLPattern,
		})
	}

	// Listeners
	for _, l := range app.Listeners {
		info.Listeners = append(info.Listeners, &ListenerInfo{
			Class: l.Class,
		})
	}

	// Context params
	for _, p := range app.ContextParams {
		info.ContextParams[p.Name] = p.Value
	}

	// Error pages
	for _, e := range app.ErrorPages {
		info.ErrorPages = append(info.ErrorPages, &ErrorPage{
			ErrorCode:     e.ErrorCode,
			ExceptionType: e.ExceptionType,
			Location:      e.Location,
		})
	}

	// Welcome files
	info.WelcomeFiles = app.WelcomeFiles.Files

	// Security constraints
	for _, sc := range app.SecurityConstr {
		info.SecurityConstraints = append(info.SecurityConstraints, &SecurityConstraint{
			WebResourceName: sc.WebResourceCollection.Name,
			URLPatterns:     sc.WebResourceCollection.URLPatterns,
			HTTPMethods:     sc.WebResourceCollection.HTTPMethods,
			AuthRoles:       sc.AuthConstraint.Roles,
		})
	}

	return info, nil
}
