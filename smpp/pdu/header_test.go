// Copyright 2015 go-smpp authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package pdu

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHeader(t *testing.T) {
	want := []byte{
		0x00, 0x00, 0x00, 0x10, // 16 Len
		0x80, 0x00, 0x00, 0x00, // GenericNACK ID
		0x00, 0x00, 0x00, 0x01, // Invalid message length Status
		0x00, 0x00, 0x00, 0x0D, // 13 Seq
	}
	h, err := DecodeHeader(bytes.NewBuffer(want))
	if err != nil {
		t.Fatal(err)
	}
	if h.Len != 16 {
		t.Fatalf("unexpected Len: want 16, have %d", h.Len)
	}
	if h.ID != GenericNACKID {
		t.Fatalf("unexpected ID: want GenericNACK, have %d", h.ID)
	}
	if h.Status != 1 {
		t.Fatalf("unexpected Status: want 1, have %d", h.Status)
	}
	if h.Seq != 13 {
		t.Fatalf("unexpected Seq: want 13, have %d", h.Seq)
	}
	var b bytes.Buffer
	if err := h.SerializeTo(&b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, b.Bytes()) {
		t.Fatalf("malformed header:\nwant:%s\nhave:\n%s",
			hex.Dump(want), hex.Dump(b.Bytes()))
	}
	we := "invalid message length"
	if have := h.Status.Error(); have != we {
		t.Fatalf("unexpected status: want %q, have %q", we, have)
	}
	h.Status = 0x2000
	we = "unknown status: 8192"
	if have := h.Status.Error(); have != we {
		t.Fatalf("unexpected status: want %q, have %q", we, have)
	}
}

func TestDecodeHeaderShort(t *testing.T) {
	h, err := DecodeHeader(bytes.NewBuffer(nil))
	if err == nil {
		t.Fatalf("unexpected parsing of no data: %#v", h)
	}
	bin := []byte{
		0x00, 0x00, 0x00, 0x01, // 1 Len
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	h, err = DecodeHeader(bytes.NewBuffer(bin))
	if err == nil {
		t.Fatalf("unexpected parsing of short Len: %#v", h)
	}
}

func TestDecodeHeaderLenBelowMax(t *testing.T) {
	bin := []byte{
		0x00, 0x00, 0xFF, 0xFF, // 64KiB Len
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	h, err := DecodeHeader(bytes.NewBuffer(bin))
	if err != nil {
		t.Fatalf("unexpected parsing of long Len: %#v", h)
	}
	if h.Len != 65535 {
		t.Fatalf("unexpected parsed header Len: %#v", h.Len)
	}
}

func TestDecodeHeaderLenAboveMax(t *testing.T) {
	bin := []byte{
		0x00, 0x01, 0x10, 0x01, // 69632 + 1 Len
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	h, err := DecodeHeader(bytes.NewBuffer(bin))
	if err == nil {
		t.Fatalf("unexpected parsing of big Len: %#v", h)
	}
	if h != nil {
		t.Fatalf("unexpected header returned:, %#v", h)
	}
}
