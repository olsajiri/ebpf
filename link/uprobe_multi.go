package link

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

type UprobeMultiOptions struct {
	Path          string
	Offsets       []uint64
	RefCtrOffsets []uint64
	Cookies       []uint64
}

func (ex *Executable) UprobeMulti(symbols []string, prog *ebpf.Program, opts *UprobeMultiOptions) (Link, error) {
	if opts == nil {
		opts = &UprobeMultiOptions{}
	}
	var err error
	if len(symbols) != 0 {
		opts.Offsets, err = ex.addressMulti(symbols)
		if err != nil {
			return nil, err
		}
	}
	return ex.uprobeMulti(prog, opts, 0)
}

func (ex *Executable) UretprobeMulti(symbols []string, prog *ebpf.Program, opts *UprobeMultiOptions) (Link, error) {
	return ex.uprobeMulti(prog, opts, unix.BPF_F_UPROBE_MULTI_RETURN)
}

func (ex *Executable) uprobeMulti(prog *ebpf.Program, opts *UprobeMultiOptions, flags uint32) (Link, error) {
	if prog == nil {
		return nil, errors.New("cannot attach a nil program")
	}

	offsets := uint32(len(opts.Offsets))
	refCtrOffsets := uint32(len(opts.RefCtrOffsets))
	cookies := uint32(len(opts.Cookies))

	if offsets == 0 {
		return nil, fmt.Errorf("Offsets is required: %w", errInvalidInput)
	}
	if refCtrOffsets > 0 && refCtrOffsets != offsets {
		return nil, fmt.Errorf("RefCtrOffsets must be exactly Offsets in length: %w", errInvalidInput)
	}
	if cookies > 0 && cookies != offsets {
		return nil, fmt.Errorf("Cookies must be exactly Offsets in length: %w", errInvalidInput)
	}

	attr := &sys.LinkCreateUprobeMultiAttr{
		Path:             sys.NewStringPointer(ex.path),
		ProgFd:           uint32(prog.FD()),
		AttachType:       sys.BPF_TRACE_UPROBE_MULTI,
		UprobeMultiFlags: flags,
		Count:            offsets,
		Offsets:          sys.NewPointer(unsafe.Pointer(&opts.Offsets[0])),
	}

	if refCtrOffsets != 0 {
		attr.RefCtrOffsets = sys.NewPointer(unsafe.Pointer(&opts.RefCtrOffsets[0]))
	}
	if cookies != 0 {
		attr.Cookies = sys.NewPointer(unsafe.Pointer(&opts.Cookies[0]))
	}

	fd, err := sys.LinkCreateUprobeMulti(attr)
	if errors.Is(err, unix.ESRCH) {
		return nil, fmt.Errorf("XXX: %w", os.ErrNotExist)
	}
	if errors.Is(err, unix.EINVAL) {
		return nil, fmt.Errorf("%w (missing kernel symbol or prog's AttachType not AttachTraceUprobeMulti?)", err)
	}

	if err != nil {
		if haveFeatErr := haveBPFLinkUprobeMulti(); haveFeatErr != nil {
			return nil, haveFeatErr
		}
		return nil, err
	}

	return &uprobeMultiLink{RawLink{fd, ""}}, nil
}

type uprobeMultiLink struct {
	RawLink
}

var _ Link = (*uprobeMultiLink)(nil)

func (kml *uprobeMultiLink) Update(prog *ebpf.Program) error {
	return fmt.Errorf("update uprobe_multi: %w", ErrNotSupported)
}

func (kml *uprobeMultiLink) Pin(string) error {
	return fmt.Errorf("pin uprobe_multi: %w", ErrNotSupported)
}

func (kml *uprobeMultiLink) Unpin() error {
	return fmt.Errorf("unpin uprobe_multi: %w", ErrNotSupported)
}

var haveBPFLinkUprobeMulti = internal.NewFeatureTest("bpf_link_uprobe_multi", "6.6", func() error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "probe_upm_link",
		Type: ebpf.Kprobe,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		AttachType: ebpf.AttachTraceUprobeMulti,
		License:    "MIT",
	})
	if errors.Is(err, unix.E2BIG) {
		// Kernel doesn't support AttachType field.
		return internal.ErrNotSupported
	}
	if err != nil {
		return err
	}
	defer prog.Close()

	fd, err := sys.LinkCreateUprobeMulti(&sys.LinkCreateUprobeMultiAttr{
		ProgFd:     uint32(prog.FD()),
		AttachType: sys.BPF_TRACE_UPROBE_MULTI,
		Path:       sys.NewStringPointer("/"),
		Offsets:    sys.NewPointer(unsafe.Pointer(&[]uint64{0})),
		Count:      1,
	})
	switch {
	case errors.Is(err, unix.EBADF):
		return nil
	case err != nil:
		return internal.ErrNotSupported
	}
	// should not happen
	fd.Close()
	return internal.ErrNotSupported
})
