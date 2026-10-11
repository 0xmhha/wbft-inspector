package rlp

import (
	"bytes"
	"testing"
)

// TestSplit decodes strings and lists in their short and long forms and
// refuses the non-canonical and truncated encodings.
func TestSplit(t *testing.T) {
	long := bytes.Repeat([]byte{7}, 56)
	enc := append([]byte{0xb8, 56}, long...)
	for name, tc := range map[string]struct {
		in      []byte
		list    bool
		content []byte
	}{
		"single byte": {[]byte{0x05}, false, []byte{0x05}},
		"empty":       {[]byte{0x80}, false, []byte{}},
		"short":       {[]byte{0x82, 0x80, 0x81}, false, []byte{0x80, 0x81}},
		"long":        {enc, false, long},
		"empty list":  {[]byte{0xc0}, true, []byte{}},
		"list":        {[]byte{0xc2, 0x01, 0x80}, true, []byte{0x01, 0x80}},
	} {
		it, rest, err := Split(tc.in)
		if err != nil || len(rest) != 0 || it.List != tc.list || !bytes.Equal(it.Content, tc.content) || !bytes.Equal(it.Raw, tc.in) {
			t.Errorf("%s: %+v %x %v", name, it, rest, err)
		}
	}
	for name, in := range map[string][]byte{
		"single byte as a string":  {0x81, 0x05},
		"long form for 55 bytes":   append([]byte{0xb8, 55}, bytes.Repeat([]byte{1}, 55)...),
		"length with leading zero": append([]byte{0xb9, 0x00, 56}, long...),
		"truncated string":         {0x83, 0x01},
		"truncated list":           {0xc3, 0x01},
		"nothing":                  {},
	} {
		if _, _, err := Split(in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := Items([]byte{0xc1, 0x01, 0x02}); err == nil {
		t.Error("trailing bytes accepted")
	}
	if v, err := (Item{Content: []byte{0x01, 0x00}}).Uint(); err != nil || v.Int64() != 256 {
		t.Errorf("uint: %v %v", v, err)
	}
	if _, err := (Item{Content: []byte{0x00, 0x01}}).Uint(); err == nil {
		t.Error("leading zero accepted")
	}
}

// TestEncode checks the list and integer encodings against their short and
// long forms.
func TestEncode(t *testing.T) {
	if got := EncodeList(EncodeUint(0), EncodeUint(0x7f), EncodeUint(0x80), EncodeUint(0x1234)); !bytes.Equal(got, []byte{0xc7, 0x80, 0x7f, 0x81, 0x80, 0x82, 0x12, 0x34}) {
		t.Errorf("short list %x", got)
	}
	item := append([]byte{0xb8, 56}, bytes.Repeat([]byte{7}, 56)...)
	got := EncodeList(item)
	if !bytes.Equal(got[:2], []byte{0xf8, 58}) || !bytes.Equal(got[2:], item) {
		t.Errorf("long list %x", got[:4])
	}
}
