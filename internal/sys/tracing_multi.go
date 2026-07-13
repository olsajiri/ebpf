package sys

import (
	"structs"
	"unsafe"
)

// tracing_multi definitions are not part of the v7.1 vmlinux BTF used by
// gentypes yet. Keep them separate from types.go so that regenerating the
// syscall bindings doesn't remove them.
const (
	BPF_TRACE_FENTRY_MULTI   AttachType = 59
	BPF_TRACE_FEXIT_MULTI    AttachType = 60
	BPF_TRACE_FSESSION_MULTI AttachType = 61

	BPF_LINK_TYPE_TRACING_MULTI LinkType = 15
)

type LinkCreateTracingMultiAttr struct {
	_          structs.HostLayout
	ProgFd     uint32
	TargetFd   uint32
	AttachType AttachType
	Flags      uint32
	Ids        TypedPointer[TypeID]
	Cookies    TypedPointer[uint64]
	Count      uint32
	_          [28]byte
}

func LinkCreateTracingMulti(attr *LinkCreateTracingMultiAttr) (*FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return NewFD(int(fd))
}
