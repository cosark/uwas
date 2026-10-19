package sftpserver

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func readReqPayload(handle string, offset uint64, length uint32) []byte {
	p := marshalString(handle)
	var b [12]byte
	binary.BigEndian.PutUint64(b[0:8], offset)
	binary.BigEndian.PutUint32(b[8:12], length)
	return append(p, b[:]...)
}

func openReqPayload(path string, pflags uint32) []byte {
	p := marshalString(path)
	p = append(p, marshalUint32(pflags)...)
	return append(p, marshalUint32(0)...) // empty ATTRS
}

// TestReadErrorIsNotReportedAsEOF pins that a failed read (here: reading a
// directory opened with SSH_FXP_OPEN, and reading a write-only handle) answers
// SSH_FX_FAILURE. It used to answer SSH_FX_EOF for every zero-byte read, so a
// client downloading such a handle (or a file hitting an I/O error) saw a clean,
// silently truncated end of file.
func TestReadErrorIsNotReportedAsEOF(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	os.WriteFile(filepath.Join(root, "f.txt"), []byte("hello"), 0644)
	os.Mkdir(filepath.Join(root, "d"), 0755)
	rt := pipeSFTP(t, root, false)

	open := func(path string, pflags uint32) string {
		t.Helper()
		typ, _, body := rt(sshFXPOpen, openReqPayload(path, pflags))
		if typ != sshFXPHandle {
			t.Fatalf("open %s: type %d status %d", path, typ, statusCode(body))
		}
		h, _ := readString(body)
		return h
	}

	// Controls: a regular file reads its data, and a read at EOF is EOF.
	h := open("f.txt", sshFXFRead)
	if typ, _, _ := rt(sshFXPRead, readReqPayload(h, 0, 100)); typ != sshFXPData {
		t.Fatalf("control: read of regular file answered type %d, want DATA", typ)
	}
	if typ, _, body := rt(sshFXPRead, readReqPayload(h, 5, 100)); typ != sshFXPStatus || statusCode(body) != sshFXEOF {
		t.Fatalf("control: read at EOF answered type %d code %d, want EOF", typ, statusCode(body))
	}

	// A directory opened as a file cannot be read: failure, not EOF.
	hd := open("d", sshFXFRead)
	typ, _, body := rt(sshFXPRead, readReqPayload(hd, 0, 100))
	if typ != sshFXPStatus || statusCode(body) != sshFXFailure {
		t.Errorf("EXPECTED: FAILURE status\nACTUAL: type %d code %d (directory read)", typ, statusCode(body))
	}

	// A write-only handle cannot be read: failure, not EOF.
	hw := open("f.txt", sshFXFWrite)
	typ, _, body = rt(sshFXPRead, readReqPayload(hw, 0, 100))
	if typ != sshFXPStatus || statusCode(body) != sshFXFailure {
		t.Errorf("EXPECTED: FAILURE status\nACTUAL: type %d code %d (write-only handle read)", typ, statusCode(body))
	}
}
