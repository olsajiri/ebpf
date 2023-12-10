package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

func TestUprobeMulti(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveBPFLinkUprobeMulti())

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	um, err := bashEx.UprobeMulti([]string{"bash_logout", "main"}, prog, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer um.Close()

	testLink(t, um, prog)
}

func TestUprobeMultiInput(t *testing.T) {
	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	// One of Symbols or Addresses must be given.
	_, err := bashEx.UprobeMulti([]string{}, prog, nil)
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got: %v", err)
	}

	// One Symbol, two cookies..
	_, err = bashEx.UprobeMulti([]string{}, prog, &UprobeMultiOptions{
		Offsets: []uint64{1},
		Cookies: []uint64{2, 3},
	})
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("expected errInvalidInput, got: %v", err)
	}
}

func TestUprobeMultiErrors(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveBPFLinkUprobeMulti())

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	// Wrong offset
	_, err := bashEx.UprobeMulti([]string{}, prog, &UprobeMultiOptions{Offsets: []uint64{1<<64 - 1}})
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("expected EINVAL, got: %s", err)
	}
}
