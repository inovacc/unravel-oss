/*
Copyright (c) 2026 Security Research
*/
package msix

import (
	"encoding/xml"
	"strings"
)

// MaxCapabilityEntries bounds the number of capability entries parsed per
// manifest to mitigate T-04-04 (capability-count DoS). Excess entries are
// dropped and CapabilitiesBlock.Truncated is set.
const MaxCapabilityEntries = 1024

// XML namespace URIs. Recognising these maps a child element to its typed
// slice and assigns the canonical namespace tag used by uwp.CapabilityRef.
const (
	nsFoundation = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
	nsRescap     = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
	nsCustom4    = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/4"
	nsUAP        = "http://schemas.microsoft.com/appx/manifest/uap/windows10"
	nsUAP2       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/2"
	nsUAP3       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
	nsUAP4       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/4"
	nsUAP6       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/6"
	nsUAP8       = "http://schemas.microsoft.com/appx/manifest/uap/windows10/8"
	nsUAP10      = "http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
	nsUAP13      = "http://schemas.microsoft.com/appx/manifest/uap/windows10/13"
	nsUAP15      = "http://schemas.microsoft.com/appx/manifest/uap/windows10/15"
)

// nameAttr returns the value of the Name="..." attribute.
func nameAttr(attrs []xml.Attr) string {
	for _, a := range attrs {
		if a.Name.Local == "Name" {
			return a.Value
		}
	}
	return ""
}

// idAttr returns the value of the Id="..." attribute.
func idAttr(attrs []xml.Attr) string {
	for _, a := range attrs {
		if a.Name.Local == "Id" {
			return a.Value
		}
	}
	return ""
}

// typeAttr returns the value of the Type="..." attribute.
func typeAttr(attrs []xml.Attr) string {
	for _, a := range attrs {
		if a.Name.Local == "Type" {
			return a.Value
		}
	}
	return ""
}

// UnmarshalXML implements xml.Unmarshaler for CapabilitiesBlock. It walks the
// child element token stream, dispatches each child to the typed slice that
// matches its (namespace, local-name) pair, and appends an OrderedCapRef so
// callers can iterate in manifest-document order regardless of namespace.
//
// Security:
//   - Bounded iteration: drops entries past MaxCapabilityEntries (T-04-04).
//   - Unknown namespaces flow into UnknownCapability rather than being
//     silently dropped — security-relevant signal preserved.
//   - DTD/entity expansion is rejected by encoding/xml at the decoder level
//     (Go 1.14+); this method never sees expanded payloads.
func (c *CapabilitiesBlock) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	idx := 0
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name == start.Name {
				return nil
			}
		case xml.StartElement:
			if idx >= MaxCapabilityEntries {
				c.Truncated = true
				if err := d.Skip(); err != nil {
					return err
				}
				continue
			}

			ns := t.Name.Space
			local := t.Name.Local

			switch local {
			case "Capability":
				name := nameAttr(t.Attr)
				cap := NamedCap{Name: name}
				switch ns {
				case "", nsFoundation:
					c.Capability = append(c.Capability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "", Name: name, Index: idx})
				case nsUAP:
					c.UAPCapability = append(c.UAPCapability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "uap", Name: name, Index: idx})
				case nsUAP2:
					c.UAP2Capability = append(c.UAP2Capability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "uap2", Name: name, Index: idx})
				case nsUAP3:
					c.UAP3Capability = append(c.UAP3Capability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "uap3", Name: name, Index: idx})
				case nsUAP4:
					c.UAP4Capability = append(c.UAP4Capability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "uap4", Name: name, Index: idx})
				case nsUAP6:
					c.UAP6Capability = append(c.UAP6Capability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "uap6", Name: name, Index: idx})
				case nsUAP8:
					c.UAP8Capability = append(c.UAP8Capability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "uap8", Name: name, Index: idx})
				case nsUAP10:
					c.UAP10Capability = append(c.UAP10Capability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "uap10", Name: name, Index: idx})
				case nsUAP13:
					c.UAP13Capability = append(c.UAP13Capability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "uap13", Name: name, Index: idx})
				case nsUAP15:
					c.UAP15Capability = append(c.UAP15Capability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "uap15", Name: name, Index: idx})
				case nsRescap:
					c.RestrictedCapability = append(c.RestrictedCapability, cap)
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "rescap", Name: name, Index: idx})
				default:
					c.UnknownCapability = append(c.UnknownCapability, cap)
					tag := "unknown"
					if ns != "" {
						tag = "unknown:" + ns
					}
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: tag, Name: name, Index: idx})
				}
				idx++
				if err := d.Skip(); err != nil {
					return err
				}

			case "DeviceCapability":
				dc := DeviceCap{Name: nameAttr(t.Attr)}
				if err := decodeDeviceChildren(d, t, &dc); err != nil {
					return err
				}
				c.DeviceCapability = append(c.DeviceCapability, dc)
				c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "device", Name: dc.Name, Index: idx})
				idx++

			case "CustomCapability":
				name := nameAttr(t.Attr)
				c.CustomCapability = append(c.CustomCapability, NamedCap{Name: name})
				c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: "custom", Name: name, Index: idx})
				idx++
				if err := d.Skip(); err != nil {
					return err
				}

			default:
				// Tolerate unknown child elements; preserve as unknown if it
				// looks like a capability (has Name attr).
				if name := nameAttr(t.Attr); name != "" && strings.HasSuffix(local, "Capability") {
					c.UnknownCapability = append(c.UnknownCapability, NamedCap{Name: name})
					tag := "unknown"
					if ns != "" {
						tag = "unknown:" + ns
					}
					c.OrderedRefs = append(c.OrderedRefs, OrderedCapRef{Namespace: tag, Name: name, Index: idx})
					idx++
				}
				if err := d.Skip(); err != nil {
					return err
				}
			}
		}
	}
}

// decodeDeviceChildren consumes the children of a <DeviceCapability> element,
// populating dc.Device with parsed <Device Id="..."> entries (and their
// <Function Type="..."/> children).
func decodeDeviceChildren(d *xml.Decoder, start xml.StartElement, dc *DeviceCap) error {
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name == start.Name {
				return nil
			}
		case xml.StartElement:
			if t.Name.Local == "Device" {
				child := DeviceChild{Id: idAttr(t.Attr)}
				if err := decodeDeviceFunctions(d, t, &child); err != nil {
					return err
				}
				dc.Device = append(dc.Device, child)
			} else {
				if err := d.Skip(); err != nil {
					return err
				}
			}
		}
	}
}

func decodeDeviceFunctions(d *xml.Decoder, start xml.StartElement, child *DeviceChild) error {
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.EndElement:
			if t.Name == start.Name {
				return nil
			}
		case xml.StartElement:
			if t.Name.Local == "Function" {
				child.Function = append(child.Function, DeviceFunc{Type: typeAttr(t.Attr)})
			}
			if err := d.Skip(); err != nil {
				return err
			}
		}
	}
}
