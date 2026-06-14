//go:build windows

package collect

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"reflect"
)

// psJSON runs a PowerShell snippet that emits JSON and decodes it into out.
// All snippets used here are strictly read-only queries.
//
// It papers over a Windows PowerShell quirk: ConvertTo-Json emits a single
// object (not an array) when a pipeline yields exactly one item. When out is a
// pointer to a slice and we got a lone object, the object is wrapped in an
// array before decoding so callers can always treat results uniformly.
func psJSON(script string, out any) error {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	data, err := cmd.Output()
	if err != nil {
		return err
	}
	data = bytes.TrimSpace(data)
	// PowerShell emits nothing for an empty result; treat that as no data.
	if len(data) == 0 {
		return nil
	}

	if wantsSlice(out) && len(data) > 0 && data[0] == '{' {
		wrapped := make([]byte, 0, len(data)+2)
		wrapped = append(wrapped, '[')
		wrapped = append(wrapped, data...)
		wrapped = append(wrapped, ']')
		data = wrapped
	}
	return json.Unmarshal(data, out)
}

// wantsSlice reports whether out is a pointer to a slice.
func wantsSlice(out any) bool {
	t := reflect.TypeOf(out)
	return t != nil && t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Slice
}
