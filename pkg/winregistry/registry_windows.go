//go:build windows

/*
Copyright (c) 2026 Security Research
*/

package winregistry

import (
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const (
	defaultDepth  = 3
	maxDepthCap   = 20
	defaultValues = 256
	maxValuesCap  = 4096
)

var hiveMap = map[string]registry.Key{
	"HKLM": registry.LOCAL_MACHINE,
	"HKCU": registry.CURRENT_USER,
	"HKCR": registry.CLASSES_ROOT,
	"HKU":  registry.USERS,
	"HKCC": registry.CURRENT_CONFIG,
}

// Dump walks every key in opts.Keys and returns a Result. Errors on
// individual keys are recorded in KeyDump.Err so a single bad path
// doesn't fail the whole dump.
func Dump(opts DumpOptions) (*Result, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultDepth
	}
	if opts.MaxDepth > maxDepthCap {
		opts.MaxDepth = maxDepthCap
	}
	if opts.MaxValuesPerKey <= 0 {
		opts.MaxValuesPerKey = defaultValues
	}
	if opts.MaxValuesPerKey > maxValuesCap {
		opts.MaxValuesPerKey = maxValuesCap
	}
	res := &Result{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Platform:    runtime.GOOS,
	}
	for _, root := range opts.Keys {
		hive, sub, err := splitHive(root)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", root, err))
			continue
		}
		walkKey(hive, sub, root, 0, &opts, res)
	}
	return res, nil
}

func splitHive(path string) (registry.Key, string, error) {
	idx := strings.IndexAny(path, `\/`)
	var head, tail string
	if idx < 0 {
		head = path
	} else {
		head = path[:idx]
		tail = strings.ReplaceAll(path[idx+1:], "/", `\`)
	}
	hive, ok := hiveMap[strings.ToUpper(head)]
	if !ok {
		return 0, "", fmt.Errorf("unknown hive %q (want HKLM/HKCU/HKCR/HKU/HKCC)", head)
	}
	return hive, tail, nil
}

func walkKey(hive registry.Key, sub, displayPath string, depth int, opts *DumpOptions, res *Result) {
	k, err := registry.OpenKey(hive, sub, registry.READ)
	if err != nil {
		res.Keys = append(res.Keys, &KeyDump{Path: displayPath, Err: err.Error()})
		return
	}
	defer func() { _ = k.Close() }()

	info, err := k.Stat()
	if err != nil {
		res.Keys = append(res.Keys, &KeyDump{Path: displayPath, Err: "stat: " + err.Error()})
		return
	}
	kd := &KeyDump{
		Path:          displayPath,
		LastWriteTime: time.Unix(0, info.ModTime().UnixNano()).UTC().Format(time.RFC3339),
		SubKeyCount:   int(info.SubKeyCount),
	}

	if !opts.DryRun {
		readValues(k, kd, opts.MaxValuesPerKey)
	}
	res.Keys = append(res.Keys, kd)

	if depth+1 >= opts.MaxDepth {
		return
	}
	subnames, err := k.ReadSubKeyNames(-1)
	if err != nil {
		kd.Err = appendErr(kd.Err, "subkeys: "+err.Error())
		return
	}
	for _, name := range subnames {
		childDisplay := displayPath + `\` + name
		childSub := sub
		if childSub == "" {
			childSub = name
		} else {
			childSub = childSub + `\` + name
		}
		walkKey(hive, childSub, childDisplay, depth+1, opts, res)
	}
}

func readValues(k registry.Key, kd *KeyDump, cap int) {
	names, err := k.ReadValueNames(-1)
	if err != nil {
		kd.Err = appendErr(kd.Err, "value names: "+err.Error())
		return
	}
	if len(names) > cap {
		names = names[:cap]
		kd.ValueTruncated = true
	}
	for _, name := range names {
		ve := readOneValue(k, name)
		kd.Values = append(kd.Values, ve)
	}
}

func readOneValue(k registry.Key, name string) ValueEntry {
	// Probe type via zero-length GetValue call.
	_, valType, err := k.GetValue(name, nil)
	if err != nil && err != registry.ErrShortBuffer {
		return ValueEntry{Name: name, Type: "REG_ERROR", String: err.Error()}
	}
	ve := ValueEntry{Name: name, Type: regTypeName(valType)}
	switch valType {
	case registry.SZ, registry.EXPAND_SZ:
		s, _, _ := k.GetStringValue(name)
		ve.String = s
	case registry.DWORD:
		v, _, _ := k.GetIntegerValue(name)
		u := uint32(v)
		ve.DWORD = &u
	case registry.QWORD:
		v, _, _ := k.GetIntegerValue(name)
		ve.QWORD = &v
	case registry.MULTI_SZ:
		ss, _, _ := k.GetStringsValue(name)
		ve.Strings = ss
	case registry.BINARY:
		b, _, _ := k.GetBinaryValue(name)
		ve.Binary = base64.StdEncoding.EncodeToString(b)
	default:
		b, _, _ := k.GetBinaryValue(name)
		ve.Binary = base64.StdEncoding.EncodeToString(b)
	}
	return ve
}

func regTypeName(t uint32) string {
	switch t {
	case registry.NONE:
		return "REG_NONE"
	case registry.SZ:
		return "REG_SZ"
	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case registry.BINARY:
		return "REG_BINARY"
	case registry.DWORD:
		return "REG_DWORD"
	case registry.DWORD_BIG_ENDIAN:
		return "REG_DWORD_BIG_ENDIAN"
	case registry.LINK:
		return "REG_LINK"
	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"
	case registry.RESOURCE_LIST:
		return "REG_RESOURCE_LIST"
	case registry.FULL_RESOURCE_DESCRIPTOR:
		return "REG_FULL_RESOURCE_DESCRIPTOR"
	case registry.RESOURCE_REQUIREMENTS_LIST:
		return "REG_RESOURCE_REQUIREMENTS_LIST"
	case registry.QWORD:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_UNKNOWN_0x%X", t)
	}
}

func appendErr(prev, add string) string {
	if prev == "" {
		return add
	}
	return prev + "; " + add
}
