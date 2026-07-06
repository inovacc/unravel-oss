/*
Copyright (c) 2026 Security Research
*/
package msix

import (
	"archive/zip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/internal/boundedzip"
	"github.com/inovacc/unravel-oss/pkg/safeio"
)

// Aggregate extraction caps for MSIX (untrusted ZIP) extraction. These are
// vars (not consts) so callers/tests can tune them. Defaults are generous so
// legitimate large packages pass; only egregious bombs trip them.
var (
	// maxMSIXTotalBytes bounds cumulative extracted bytes across all entries.
	maxMSIXTotalBytes int64 = 4 << 30 // 4 GiB
	// maxMSIXEntries bounds the number of extracted entries.
	maxMSIXEntries int64 = 100_000
)

// NamedCap represents any <Capability Name="..."/> element.
type NamedCap struct {
	Name string `xml:"Name,attr" json:"name"`
}

// DeviceCap represents <DeviceCapability Name="..."> with optional Device children.
type DeviceCap struct {
	Name   string        `xml:"Name,attr" json:"name"`
	Device []DeviceChild `xml:"Device" json:"device,omitempty"`
}

// DeviceChild represents a <Device Id="..."> element with optional Function entries.
type DeviceChild struct {
	Id       string       `xml:"Id,attr" json:"id"`
	Function []DeviceFunc `xml:"Function" json:"function,omitempty"`
}

// DeviceFunc represents <Function Type="..."/>.
type DeviceFunc struct {
	Type string `xml:"Type,attr" json:"type"`
}

// OrderedCapRef preserves the cross-tag manifest order of capabilities (D-04).
type OrderedCapRef struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Index     int    `json:"index"`
}

// CapabilitiesBlock is the parsed <Capabilities> sub-element of an AppxManifest.
// It uses a custom UnmarshalXML implementation so that OrderedRefs preserves the
// cross-namespace document order of capability declarations.
type CapabilitiesBlock struct {
	Capability           []NamedCap  `json:"capability,omitempty"`
	UAPCapability        []NamedCap  `json:"uap_capability,omitempty"`
	UAP2Capability       []NamedCap  `json:"uap2_capability,omitempty"`
	UAP3Capability       []NamedCap  `json:"uap3_capability,omitempty"`
	UAP4Capability       []NamedCap  `json:"uap4_capability,omitempty"`
	UAP6Capability       []NamedCap  `json:"uap6_capability,omitempty"`
	UAP8Capability       []NamedCap  `json:"uap8_capability,omitempty"`
	UAP10Capability      []NamedCap  `json:"uap10_capability,omitempty"`
	UAP13Capability      []NamedCap  `json:"uap13_capability,omitempty"`
	UAP15Capability      []NamedCap  `json:"uap15_capability,omitempty"`
	RestrictedCapability []NamedCap  `json:"restricted_capability,omitempty"`
	DeviceCapability     []DeviceCap `json:"device_capability,omitempty"`
	CustomCapability     []NamedCap  `json:"custom_capability,omitempty"`
	UnknownCapability    []NamedCap  `json:"unknown_capability,omitempty"`

	// OrderedRefs preserves the cross-tag manifest order; bounded to MaxCapabilityEntries
	// to mitigate T-04-04 capability-count DoS attacks.
	OrderedRefs []OrderedCapRef `json:"ordered_refs,omitempty"`

	// Truncated is set when more than MaxCapabilityEntries capabilities were
	// encountered; remaining entries are dropped.
	Truncated bool `json:"truncated,omitempty"`
}

// AppxManifest represents the parsed AppxManifest.xml.
type AppxManifest struct {
	XMLName  xml.Name `xml:"Package"`
	Identity struct {
		Name                  string `xml:"Name,attr" json:"name"`
		Version               string `xml:"Version,attr" json:"version"`
		Publisher             string `xml:"Publisher,attr" json:"publisher"`
		ProcessorArchitecture string `xml:"ProcessorArchitecture,attr" json:"processor_architecture"`
	} `xml:"Identity" json:"identity"`
	Properties struct {
		DisplayName          string `xml:"DisplayName" json:"display_name"`
		Description          string `xml:"Description" json:"description"`
		PublisherDisplayName string `xml:"PublisherDisplayName" json:"publisher_display_name"`
	} `xml:"Properties" json:"properties"`
	Dependencies struct {
		TargetDeviceFamily []struct {
			Name             string `xml:"Name,attr" json:"name"`
			MinVersion       string `xml:"MinVersion,attr" json:"min_version"`
			MaxVersionTested string `xml:"MaxVersionTested,attr" json:"max_version_tested"`
		} `xml:"TargetDeviceFamily" json:"target_device_family"`
	} `xml:"Dependencies" json:"dependencies"`
	Capabilities CapabilitiesBlock `xml:"Capabilities" json:"capabilities"`
	Applications struct {
		Application []AppxApplication `xml:"Application" json:"application"`
	} `xml:"Applications" json:"applications"`
}

// AppxApplication is the parsed shape of a single <Application> node inside
// an AppxManifest. Promoted from anonymous to named in P69-01 so that
// flattenApplicationExtensions (and dir.go's mirror loop) can take a typed
// argument instead of an inline struct literal.
type AppxApplication struct {
	ID             string                `xml:"Id,attr" json:"id"`
	Executable     string                `xml:"Executable,attr" json:"executable"`
	EntryPoint     string                `xml:"EntryPoint,attr" json:"entry_point"`
	VisualElements AppxVisualElementsXML `xml:"VisualElements" json:"visual_elements"`
	Extensions     struct {
		Extension []AppxExtensionXML `xml:"Extension" json:"extension"`
	} `xml:"Extensions" json:"extensions"`
}

// AppxVisualElementsXML is the parsed-XML mirror of <uap:VisualElements>.
type AppxVisualElementsXML struct {
	DisplayName       string `xml:"DisplayName,attr,omitempty" json:"display_name,omitempty"`
	Description       string `xml:"Description,attr,omitempty" json:"description,omitempty"`
	BackgroundColor   string `xml:"BackgroundColor,attr,omitempty" json:"background_color,omitempty"`
	Square150x150Logo string `xml:"Square150x150Logo,attr,omitempty" json:"square150x150_logo,omitempty"`
	Square44x44Logo   string `xml:"Square44x44Logo,attr,omitempty" json:"square44x44_logo,omitempty"`
}

// AppxExtensionXML is the parsed-XML mirror of a single <Extension> entry.
// Field set was extended in P69-01 (D-69-03) to cover windows.shareTarget,
// windows.activatableClass.* (InProcessServer), and windows.protocol.
type AppxExtensionXML struct {
	Category   string `xml:"Category,attr" json:"category"`
	EntryPoint string `xml:"EntryPoint,attr,omitempty" json:"entry_point,omitempty"`
	Executable string `xml:"Executable,attr,omitempty" json:"executable,omitempty"`
	StartPage  string `xml:"StartPage,attr,omitempty" json:"start_page,omitempty"`
	AppService struct {
		Name string `xml:"Name,attr" json:"name"`
	} `xml:"AppService" json:"app_service"`
	Protocol struct {
		Name string `xml:"Name,attr" json:"name"`
	} `xml:"Protocol" json:"protocol"`
	FileTypeAssociation struct {
		Name               string `xml:"Name,attr" json:"name"`
		SupportedFileTypes struct {
			FileType []string `xml:"FileType" json:"file_type"`
		} `xml:"SupportedFileTypes" json:"supported_file_types"`
	} `xml:"FileTypeAssociation" json:"file_type_association"`
	ShareTarget struct {
		SupportedFileTypes struct {
			SupportedType []string `xml:"SupportedType" json:"supported_type"`
		} `xml:"SupportedFileTypes" json:"supported_file_types"`
	} `xml:"ShareTarget" json:"share_target"`
	BackgroundTasks struct {
		Task []struct {
			Type string `xml:"Type,attr" json:"type"`
		} `xml:"Task" json:"task"`
	} `xml:"BackgroundTasks" json:"background_tasks"`
	InProcessServer struct {
		Path             string `xml:"Path" json:"path,omitempty"`
		ActivatableClass []struct {
			ActivatableClassId string `xml:"ActivatableClassId,attr" json:"activatable_class_id"`
		} `xml:"ActivatableClass" json:"activatable_class,omitempty"`
	} `xml:"InProcessServer" json:"in_process_server"`
	ComServer struct {
		ExeServer []struct {
			Executable string `xml:"Executable,attr" json:"executable"`
			Class      []struct {
				ID          string `xml:"Id,attr" json:"id"`
				DisplayName string `xml:"DisplayName,attr,omitempty" json:"display_name,omitempty"`
			} `xml:"Class" json:"class"`
		} `xml:"ExeServer" json:"exe_server"`
		SurrogateServer []struct {
			Class []struct {
				ID   string `xml:"Id,attr" json:"id"`
				Path string `xml:"Path,attr,omitempty" json:"path,omitempty"`
			} `xml:"Class" json:"class"`
		} `xml:"SurrogateServer" json:"surrogate_server"`
	} `xml:"ComServer" json:"com_server"`
}

// AppExtension is a flattened summary of a single AppxManifest <Extension>
// entry. Captures the most security-relevant categories (AppService, Protocol,
// FileTypeAssociation, ComServer, BackgroundTasks) so the knowledge layer can
// surface IPC + protocol-handler surface without re-parsing XML.
type AppExtension struct {
	Category   string   `json:"category"`
	AppName    string   `json:"app_name,omitempty"`
	EntryPoint string   `json:"entry_point,omitempty"`
	Executable string   `json:"executable,omitempty"`
	StartPage  string   `json:"start_page,omitempty"`
	Name       string   `json:"name,omitempty"`
	FileTypes  []string `json:"file_types,omitempty"`
	TaskTypes  []string `json:"task_types,omitempty"`
	ComClasses []string `json:"com_classes,omitempty"`
	// Protocol is the windows.protocol scheme name (e.g. "whatsapp").
	// Added in P69-01 (D-69-03) to surface protocol-handler attack surface.
	Protocol string `json:"protocol,omitempty"`
	// AppServiceName mirrors Name for windows.appService extensions and is
	// duplicated as a dedicated field so the knowledge layer can match on it
	// without ambiguity vs FileTypeAssociation.Name.
	AppServiceName string `json:"app_service_name,omitempty"`
	// ActivatableClassIDs collects every <ActivatableClass ActivatableClassId>
	// under windows.activatableClass.* extensions (InProcessServer).
	ActivatableClassIDs []string `json:"activatable_class_ids,omitempty"`
	// ShareTargetSupportedTypes lists MIME types declared by a
	// windows.shareTarget extension (incoming-share IPC surface).
	ShareTargetSupportedTypes []string `json:"share_target_supported_types,omitempty"`
}

// VisualElements is a flattened summary of a single <uap:VisualElements>
// declaration. Surfaces declared UI identity (display name, background color,
// logo asset paths) so the knowledge layer can cite UWP shell-visible surface
// without re-parsing XML. Added in P69-01 (D-69-03).
type VisualElements struct {
	AppName           string `json:"app_name,omitempty"`
	DisplayName       string `json:"display_name,omitempty"`
	Description       string `json:"description,omitempty"`
	BackgroundColor   string `json:"background_color,omitempty"`
	Square150x150Logo string `json:"square150x150_logo,omitempty"`
	Square44x44Logo   string `json:"square44x44_logo,omitempty"`
}

// Application describes an entry point in the MSIX package.
type Application struct {
	ID         string `json:"id"`
	Executable string `json:"executable"`
	EntryPoint string `json:"entry_point,omitempty"`
}

// Dependency describes a target device family dependency.
type Dependency struct {
	Name             string `json:"name"`
	MinVersion       string `json:"min_version"`
	MaxVersionTested string `json:"max_version_tested,omitempty"`
}

// InfoResult contains metadata about an MSIX package.
type InfoResult struct {
	Path                  string         `json:"path"`
	FileName              string         `json:"file_name"`
	Size                  int64          `json:"size"`
	PackageName           string         `json:"package_name"`
	PackageVersion        string         `json:"package_version"`
	Publisher             string         `json:"publisher"`
	ProcessorArchitecture string         `json:"processor_architecture,omitempty"`
	DisplayName           string         `json:"display_name,omitempty"`
	Description           string         `json:"description,omitempty"`
	PublisherDisplayName  string         `json:"publisher_display_name,omitempty"`
	MinOSVersion          string         `json:"min_os_version,omitempty"`
	Dependencies          []Dependency   `json:"dependencies,omitempty"`
	Capabilities          []string       `json:"capabilities,omitempty"`
	Applications          []Application  `json:"applications,omitempty"`
	Extensions            []AppExtension `json:"extensions,omitempty"`
	// VisualElements lists per-Application <uap:VisualElements> declarations.
	// Added in P69-01 (D-69-03) — was previously dropped on the floor.
	VisualElements  []VisualElements `json:"visual_elements,omitempty"`
	FileCount       int              `json:"file_count"`
	TotalSize       int64            `json:"total_size"`
	HasSignature    bool             `json:"has_signature"`
	HasBlockMap     bool             `json:"has_block_map"`
	HasContentTypes bool             `json:"has_content_types"`
	Files           []FileEntry      `json:"files,omitempty"`
	// ManifestPath is the path to AppxManifest.xml. For zip input (Info)
	// it is the package-relative entry name ("AppxManifest.xml"); for
	// install-dir input (InfoFromDir) it is the absolute on-disk path.
	// Used by SCRG-05 (behavior scorer) as the typed-field Citation source
	// for capability-derived Evidence — replaces generic r.SourcePath.
	// Added in P64 task 64-00b.
	ManifestPath string `json:"manifest_path,omitempty"`
	// URLs is a deduped list of HTTP(S) endpoints discovered by string
	// scanning the package's PE / JS / JSON / HTML files. Bounded.
	URLs []string `json:"urls,omitempty"`
}

// FileEntry represents a file inside the MSIX package.
type FileEntry struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	// Signed is set by post-walk Authenticode scan when the entry is a PE
	// (.exe / .dll). Unset for non-PE entries. nil pointer means "not
	// scanned"; false means "scanned, no signature"; true means "signed".
	Signed *bool  `json:"signed,omitempty"`
	Signer string `json:"signer,omitempty"`
}

// ExtractReport summarizes an MSIX extraction.
type ExtractReport struct {
	Source      string   `json:"source"`
	Output      string   `json:"output"`
	Files       int      `json:"files"`
	Directories int      `json:"directories"`
	TotalSize   int64    `json:"total_size"`
	Errors      []string `json:"errors,omitempty"`
}

// VerifyResult contains signature verification results.
type VerifyResult struct {
	Path         string `json:"path"`
	FileName     string `json:"file_name"`
	HasSignature bool   `json:"has_signature"`
	HasBlockMap  bool   `json:"has_block_map"`
}

// IsMSIX checks if a file is an MSIX package (ZIP with AppxManifest.xml).
func IsMSIX(path string) bool {
	r, err := boundedzip.OpenReader(path, boundedzip.DefaultOptions())
	if err != nil {
		return false
	}

	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		if strings.EqualFold(f.Name, "AppxManifest.xml") {
			return true
		}
	}

	return false
}

// Info parses an MSIX package and returns metadata.
func Info(msixPath string) (*InfoResult, error) {
	absPath, err := filepath.Abs(msixPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	stat, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat file: %w", err)
	}

	r, err := boundedzip.OpenReader(absPath, boundedzip.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = r.Close() }()

	result := &InfoResult{
		Path:     absPath,
		FileName: filepath.Base(absPath),
		Size:     stat.Size(),
	}

	var totalSize int64

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		result.FileCount++
		totalSize += int64(f.UncompressedSize64)

		result.Files = append(result.Files, FileEntry{
			Name: f.Name,
			Size: int64(f.UncompressedSize64),
		})

		switch {
		case strings.EqualFold(f.Name, "AppxSignature.p7x"):
			result.HasSignature = true
		case strings.EqualFold(f.Name, "AppxBlockMap.xml"):
			result.HasBlockMap = true
		case strings.EqualFold(f.Name, "[Content_Types].xml"):
			result.HasContentTypes = true
		case strings.EqualFold(f.Name, "AppxManifest.xml"):
			// Stamp the package-relative entry name as the canonical
			// reference for files inside the .msix archive (P64 64-00b).
			result.ManifestPath = f.Name
			if err := parseManifest(f, result); err != nil {
				return nil, fmt.Errorf("parse manifest: %w", err)
			}
		}
	}

	result.TotalSize = totalSize

	return result, nil
}

// ParseAppxManifest parses raw AppxManifest.xml bytes into a typed
// *AppxManifest. It is wrapped in defer/recover (T-04-04) so a malformed
// manifest never panics the caller. encoding/xml rejects DTDs and external
// entity references by default (Go 1.14+), neutralising billion-laughs.
func ParseAppxManifest(data []byte) (m *AppxManifest, err error) {
	defer func() {
		if r := recover(); r != nil {
			m = nil
			err = fmt.Errorf("appx manifest panic: %v", r)
		}
	}()

	var parsed AppxManifest
	if err := xml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("unmarshal appx manifest: %w", err)
	}
	return &parsed, nil
}

// maxManifestBytes caps AppxManifest.xml reads at 16 MiB — no legitimate
// MSIX manifest is larger than a few hundred KB.
const maxManifestBytes = 16 << 20 // 16 MiB

func parseManifest(f *zip.File, result *InfoResult) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}

	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(io.LimitReader(rc, maxManifestBytes))
	if err != nil {
		return err
	}

	parsed, err := ParseAppxManifest(data)
	if err != nil {
		return err
	}
	manifest := *parsed

	result.PackageName = manifest.Identity.Name
	result.PackageVersion = manifest.Identity.Version
	result.Publisher = manifest.Identity.Publisher
	result.ProcessorArchitecture = manifest.Identity.ProcessorArchitecture
	result.DisplayName = manifest.Properties.DisplayName
	result.Description = manifest.Properties.Description
	result.PublisherDisplayName = manifest.Properties.PublisherDisplayName

	for _, dep := range manifest.Dependencies.TargetDeviceFamily {
		d := Dependency{
			Name:             dep.Name,
			MinVersion:       dep.MinVersion,
			MaxVersionTested: dep.MaxVersionTested,
		}

		result.Dependencies = append(result.Dependencies, d)

		if result.MinOSVersion == "" || dep.MinVersion < result.MinOSVersion {
			result.MinOSVersion = dep.MinVersion
		}
	}

	for _, cap := range manifest.Capabilities.Capability {
		result.Capabilities = append(result.Capabilities, cap.Name)
	}

	for _, cap := range manifest.Capabilities.RestrictedCapability {
		result.Capabilities = append(result.Capabilities, "restricted:"+cap.Name)
	}

	for _, app := range manifest.Applications.Application {
		result.Applications = append(result.Applications, Application{
			ID:         app.ID,
			Executable: app.Executable,
			EntryPoint: app.EntryPoint,
		})
		flattenApplicationExtensions(app.ID, app.Extensions.Extension, result)
		ve := app.VisualElements
		if ve.DisplayName != "" || ve.Description != "" || ve.BackgroundColor != "" ||
			ve.Square150x150Logo != "" || ve.Square44x44Logo != "" {
			result.VisualElements = append(result.VisualElements, VisualElements{
				AppName:           app.ID,
				DisplayName:       ve.DisplayName,
				Description:       ve.Description,
				BackgroundColor:   ve.BackgroundColor,
				Square150x150Logo: ve.Square150x150Logo,
				Square44x44Logo:   ve.Square44x44Logo,
			})
		}
	}

	return nil
}

// flattenApplicationExtensions walks every <Extension> under an <Application>
// and appends a flattened AppExtension to result.Extensions per entry. Mirrors
// the dir.go::InfoFromDir loop so zip-mode (Info) and dir-mode produce the same
// shape (D-69-03). Missing nodes yield zero-value fields — no error.
func flattenApplicationExtensions(appID string, exts []AppxExtensionXML, result *InfoResult) {
	for _, ext := range exts {
		ae := AppExtension{
			Category:   ext.Category,
			AppName:    appID,
			EntryPoint: ext.EntryPoint,
			Executable: ext.Executable,
			StartPage:  ext.StartPage,
		}
		switch {
		case ext.AppService.Name != "":
			ae.Name = ext.AppService.Name
			ae.AppServiceName = ext.AppService.Name
		case ext.Protocol.Name != "":
			ae.Name = ext.Protocol.Name
			ae.Protocol = ext.Protocol.Name
		case ext.FileTypeAssociation.Name != "":
			ae.Name = ext.FileTypeAssociation.Name
			ae.FileTypes = append(ae.FileTypes, ext.FileTypeAssociation.SupportedFileTypes.FileType...)
		}
		for _, t := range ext.BackgroundTasks.Task {
			if t.Type != "" {
				ae.TaskTypes = append(ae.TaskTypes, t.Type)
			}
		}
		for _, exe := range ext.ComServer.ExeServer {
			for _, cls := range exe.Class {
				if cls.ID != "" {
					ae.ComClasses = append(ae.ComClasses, cls.ID)
				}
			}
		}
		for _, sur := range ext.ComServer.SurrogateServer {
			for _, cls := range sur.Class {
				if cls.ID != "" {
					ae.ComClasses = append(ae.ComClasses, cls.ID)
				}
			}
		}
		for _, ac := range ext.InProcessServer.ActivatableClass {
			if ac.ActivatableClassId != "" {
				ae.ActivatableClassIDs = append(ae.ActivatableClassIDs, ac.ActivatableClassId)
			}
		}
		ae.ShareTargetSupportedTypes = append(ae.ShareTargetSupportedTypes, ext.ShareTarget.SupportedFileTypes.SupportedType...)
		result.Extensions = append(result.Extensions, ae)
	}
}

// Extract unzips an MSIX package to a directory.
func Extract(msixPath, outputDir string) (*ExtractReport, error) {
	absPath, err := filepath.Abs(msixPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	r, err := boundedzip.OpenReader(absPath, boundedzip.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = r.Close() }()

	if outputDir == "" {
		base := filepath.Base(absPath)
		outputDir = strings.TrimSuffix(base, filepath.Ext(base)) + "_extracted"
	}

	report := &ExtractReport{
		Source: absPath,
		Output: outputDir,
	}

	// SEC: boundedzip.OpenReader only opens the archive; its per-file/total
	// caps are enforced by CopyEntry/ReadEntry, which this loop does not use.
	// Without an aggregate guard, a tiny .msix listing many entries (or many
	// near-512-MiB entries) writes terabytes to disk. Track aggregate bytes +
	// entry count and abort once a generous cap is exceeded.
	budget := safeio.NewBudget()
	budget.MaxTotalBytes = maxMSIXTotalBytes
	budget.MaxEntries = maxMSIXEntries
	budget.MaxEntryBytes = maxExtractedFileBytes

	for _, f := range r.File {
		targetPath := filepath.Join(outputDir, f.Name)

		// Prevent path traversal
		if !strings.HasPrefix(filepath.Clean(targetPath), filepath.Clean(outputDir)+string(os.PathSeparator)) &&
			filepath.Clean(targetPath) != filepath.Clean(outputDir) {
			report.Errors = append(report.Errors, fmt.Sprintf("skipped (path traversal): %s", f.Name))
			continue
		}

		if f.FileInfo().IsDir() {
			// Count directory entries against the entry-count budget so a
			// "many tiny dir records" bomb cannot exhaust inodes.
			if err := budget.Add(0); err != nil {
				return report, fmt.Errorf("aggregate extraction limit: %w", err)
			}
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("mkdir: %v", err))
			}

			report.Directories++

			continue
		}

		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("mkdir: %v", err))
			continue
		}

		n, err := extractFile(f, targetPath)
		if err != nil {
			// An over-cap entry is SKIPPED (dropped + warned), not written as a
			// truncated partial, and does not abort the whole package.
			if errors.Is(err, safeio.ErrLimitExceeded) {
				slog.Warn("skipping over-cap msix entry (would truncate)", "name", f.Name, "cap_bytes", maxExtractedFileBytes)
				report.Errors = append(report.Errors, fmt.Sprintf("skipped (exceeds %d-byte per-file cap): %s", maxExtractedFileBytes, f.Name))
				continue
			}
			report.Errors = append(report.Errors, fmt.Sprintf("extract %s: %v", f.Name, err))
			continue
		}

		// Account the ACTUAL bytes written (not the declared size) against the
		// aggregate budget. A breach aborts the run with a clear error.
		if err := budget.Add(n); err != nil {
			return report, fmt.Errorf("aggregate extraction limit: %w", err)
		}

		report.Files++
		report.TotalSize += n
	}

	return report, nil
}

// maxExtractedFileBytes is the per-file decompressed cap. An entry exceeding it
// is SKIPPED (dropped + caller-warned via safeio.ErrLimitExceeded), never
// written as a silently truncated partial. A var (not a const) so tests can
// inject a small cap.
var maxExtractedFileBytes int64 = 512 << 20 // 512 MiB per-file cap

// extractFile writes one zip entry to targetPath, bounded by the per-file cap,
// and returns the number of bytes written so the caller can enforce the
// aggregate budget. An entry strictly larger than the per-file cap is NOT
// truncated: the partial file is removed and safeio.ErrLimitExceeded is returned
// so the caller can skip the entry rather than emit a corrupt partial.
func extractFile(f *zip.File, targetPath string) (int64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, err
	}

	defer func() { _ = rc.Close() }()

	out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode())
	if err != nil {
		return 0, err
	}

	defer func() { _ = out.Close() }()

	n, err := safeio.CopyLimit(out, rc, maxExtractedFileBytes)
	if err != nil {
		if errors.Is(err, safeio.ErrLimitExceeded) {
			_ = out.Close()
			_ = os.Remove(targetPath)
		}
		return n, err
	}

	return n, nil
}

// Verify checks an MSIX package for digital signatures.
func Verify(msixPath string) (*VerifyResult, error) {
	absPath, err := filepath.Abs(msixPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}

	r, err := boundedzip.OpenReader(absPath, boundedzip.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	defer func() { _ = r.Close() }()

	result := &VerifyResult{
		Path:     absPath,
		FileName: filepath.Base(absPath),
	}

	for _, f := range r.File {
		switch {
		case strings.EqualFold(f.Name, "AppxSignature.p7x"):
			result.HasSignature = true
		case strings.EqualFold(f.Name, "AppxBlockMap.xml"):
			result.HasBlockMap = true
		}
	}

	return result, nil
}

// FormatBytes formats a byte count as a human-readable string.
func FormatBytes(size int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)

	switch {
	case size >= gb:
		return fmt.Sprintf("%.1f GB", float64(size)/float64(gb))
	case size >= mb:
		return fmt.Sprintf("%.1f MB", float64(size)/float64(mb))
	case size >= kb:
		return fmt.Sprintf("%.1f KB", float64(size)/float64(kb))
	default:
		return fmt.Sprintf("%d bytes", size)
	}
}
