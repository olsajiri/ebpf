package link

import (
	"errors"
	"math"
	"os"
	"os/exec"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/go-quicktest/qt"
)

func TestUprobeMulti(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveBPFLinkUprobeMulti())

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	// uprobe
	um, err := bashEx.UprobeMulti(bashSyms, prog, nil)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, um, prog)
	_ = um.Close()

	// uretprobe
	um, err = bashEx.UretprobeMulti(bashSyms, prog, nil)
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, um, prog)
	_ = um.Close()
}

func TestUprobeMultiInput(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveBPFLinkUprobeMulti())

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	// Always doing same test for both uprobe and uretprobe

	// One of symbols or offsets must be given.
	_, err := bashEx.UprobeMulti([]string{}, prog, nil)
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = bashEx.UretprobeMulti([]string{}, prog, nil)
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// One address, two cookies.
	_, err = bashEx.UprobeMulti([]string{}, prog, &UprobeMultiOptions{
		Addresses: []uint64{1},
		Cookies:   []uint64{2, 3},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = bashEx.UretprobeMulti([]string{}, prog, &UprobeMultiOptions{
		Addresses: []uint64{1},
		Cookies:   []uint64{2, 3},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Two addresses, one refctr offset.
	_, err = bashEx.UprobeMulti([]string{}, prog, &UprobeMultiOptions{
		Addresses:     []uint64{1, 2},
		RefCtrOffsets: []uint64{4},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = bashEx.UretprobeMulti([]string{}, prog, &UprobeMultiOptions{
		Addresses:     []uint64{1, 2},
		RefCtrOffsets: []uint64{4},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// It's either symbols or addresses.
	_, err = bashEx.UprobeMulti(bashSyms, prog, &UprobeMultiOptions{
		Addresses: []uint64{1},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = bashEx.UretprobeMulti(bashSyms, prog, &UprobeMultiOptions{
		Addresses: []uint64{1},
	})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// No addresses and no symbols
	_, err = bashEx.UprobeMulti([]string{}, prog, nil)
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	_, err = bashEx.UretprobeMulti([]string{}, prog, nil)
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// PID not found
	_, err = bashEx.UprobeMulti(bashSyms, prog, &UprobeMultiOptions{
		PID: math.MaxUint32,
	})
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))

	_, err = bashEx.UretprobeMulti(bashSyms, prog, &UprobeMultiOptions{
		PID: math.MaxUint32,
	})
	qt.Assert(t, qt.ErrorIs(err, os.ErrNotExist))
}

func TestUprobeMultiResolveOk(t *testing.T) {
	addrSym1, err := bashEx.address(bashSyms[0], 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	addrSym2, err := bashEx.address(bashSyms[1], 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	addrSym3, err := bashEx.address(bashSyms[2], 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	opts := &UprobeMultiOptions{}

	err = bashEx.uprobeMultiResolve(bashSyms, opts)
	if err != nil {
		t.Fatal(err)
	}

	qt.Assert(t, qt.Equals(len(opts.Addresses), 3))
	qt.Assert(t, qt.Equals(opts.Addresses[0], addrSym1))
	qt.Assert(t, qt.Equals(opts.Addresses[1], addrSym2))
	qt.Assert(t, qt.Equals(opts.Addresses[2], addrSym3))

	opts = &UprobeMultiOptions{
		Offsets: []uint64{5, 10, 11}}

	err = bashEx.uprobeMultiResolve(bashSyms, opts)
	if err != nil {
		t.Fatal(err)
	}

	qt.Assert(t, qt.Equals(len(opts.Addresses), 3))
	qt.Assert(t, qt.Equals(opts.Addresses[0], addrSym1+5))
	qt.Assert(t, qt.Equals(opts.Addresses[1], addrSym2+10))
	qt.Assert(t, qt.Equals(opts.Addresses[2], addrSym3+11))

	opts = &UprobeMultiOptions{
		Addresses: []uint64{addrSym1, addrSym2, addrSym3}}

	err = bashEx.uprobeMultiResolve(nil, opts)
	if err != nil {
		t.Fatal(err)
	}

	qt.Assert(t, qt.Equals(len(opts.Addresses), 3))
	qt.Assert(t, qt.Equals(opts.Addresses[0], addrSym1))
	qt.Assert(t, qt.Equals(opts.Addresses[1], addrSym2))
	qt.Assert(t, qt.Equals(opts.Addresses[2], addrSym3))

	opts = &UprobeMultiOptions{
		Addresses: []uint64{addrSym1, addrSym2, addrSym3},
		Offsets:   []uint64{5, 10, 11}}

	err = bashEx.uprobeMultiResolve(nil, opts)
	if err != nil {
		t.Fatal(err)
	}

	qt.Assert(t, qt.Equals(len(opts.Addresses), 3))
	qt.Assert(t, qt.Equals(opts.Addresses[0], addrSym1+5))
	qt.Assert(t, qt.Equals(opts.Addresses[1], addrSym2+10))
	qt.Assert(t, qt.Equals(opts.Addresses[2], addrSym3+11))
}

func TestUprobeMultiResolveFail(t *testing.T) {
	// No input
	err := bashEx.uprobeMultiResolve(nil, &UprobeMultiOptions{})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Different dimensions for Addresses and Offsets
	err = bashEx.uprobeMultiResolve(nil, &UprobeMultiOptions{
		Addresses: []uint64{100, 200},
		Offsets:   []uint64{5, 10, 11}})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))

	// Different dimensions for symbols and Offsets
	err = bashEx.uprobeMultiResolve(bashSyms, &UprobeMultiOptions{
		Offsets: []uint64{5, 10}})
	qt.Assert(t, qt.ErrorIs(err, errInvalidInput))
}

func TestUprobeMultiCookie(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveBPFLinkUprobeMulti())

	prog := mustLoadProgram(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti, "")

	// uprobe
	um, err := bashEx.UprobeMulti(bashSyms, prog,
		&UprobeMultiOptions{
			Cookies: []uint64{1, 2, 3},
		})
	if err != nil {
		t.Fatal(err)
	}
	_ = um.Close()

	// uretprobe
	um, err = bashEx.UretprobeMulti(bashSyms, prog,
		&UprobeMultiOptions{
			Cookies: []uint64{3, 2, 1},
		})
	if err != nil {
		t.Fatal(err)
	}
	_ = um.Close()
}

func TestUprobeMultiProgramCall(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveBPFLinkUprobeMulti())

	// We execute 'bash --help'
	args := []string{"--help"}
	elf := "/bin/bash"

	test := func(retprobe bool, expected uint32) {
		m, p := newUpdaterMapProg(t, ebpf.Kprobe, ebpf.AttachTraceUprobeMulti)

		var err error

		// Load the executable.
		ex, err := OpenExecutable(elf)
		if err != nil {
			t.Fatal(err)
		}

		var um Link

		// Open UprobeMulti on the executable for the given symbol
		// and attach it to the ebpf program created above.
		if retprobe {
			um, err = ex.UretprobeMulti(bashSyms, p, nil)
		} else {
			um, err = ex.UprobeMulti(bashSyms, p, nil)
		}
		if errors.Is(err, ErrNoSymbol) {
			// Assume bash_Syms symbols always exist and skip the test
			// if the symbol can't be found as certain OS (eg. Debian)
			// strip binaries.
			t.Skipf("executable %s appear to be stripped, skipping", elf)
		}
		if err != nil {
			t.Fatal(err)
		}

		// Trigger ebpf program call.
		trigger := func(t *testing.T) {
			if err := exec.Command(elf, args...).Run(); err != nil {
				t.Fatal(err)
			}
		}
		trigger(t)

		// Detach link.
		if err := um.Close(); err != nil {
			t.Fatal(err)
		}

		assertMapValueGE(t, m, 0, expected)

		// Reset map value to 0 at index 0.
		if err := m.Update(uint32(0), uint32(0), ebpf.UpdateExist); err != nil {
			t.Fatal(err)
		}

		// Retrigger the ebpf program call.
		trigger(t)

		// Assert that this time the value has not been updated.
		assertMapValue(t, m, 0, 0)
	}

	// all 3 uprobes should trigger for entry uprobes
	test(false, 3)

	// We have return uprobe installed on main, _start and check_dev_tty
	// functions, but only check_dev_tty is triggered, because 'bash --help'
	// calls exit(0).
	test(true, 1)
}

func TestHaveBPFLinkUprobeMulti(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFLinkUprobeMulti)
}
