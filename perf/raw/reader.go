package raw

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrClosed = os.ErrClosed
	ErrEOR    = errors.New("end of ring")
)

type Reader struct {
	deadline    time.Time
	poller      *epoll.Poller
	rings       []*EventRing
	epollEvents []unix.EpollEvent
	epollRings  []*EventRing
}

func NewReader(nCPU, perCPUBuffer, watermark int) (*Reader, error) {
	if perCPUBuffer < 1 {
		return nil, errors.New("perCPUBuffer must be larger than 0")
	}

	var rings = make([]*EventRing, 0, nCPU)

	poller, err := epoll.New()
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			poller.Close()
			for _, ring := range rings {
				if ring != nil {
					ring.Close()
				}
			}
		}
	}()

	// bpf_perf_event_output checks which CPU an event is enabled on,
	// but doesn't allow using a wildcard like -1 to specify "all CPUs".
	// Hence we have to create a ring for each CPU.
	for i := 0; i < nCPU; i++ {
		ring, err := NewPerfEventRing(i, perCPUBuffer, watermark)
		if errors.Is(err, unix.ENODEV) {
			// The requested CPU is currently offline, skip it.
			rings = append(rings, nil)
			continue
		}

		if err != nil {
			return nil, fmt.Errorf("failed to create perf ring for CPU %d: %v", i, err)
		}
		rings = append(rings, ring)

		if err := poller.Add(ring.Fd, i); err != nil {
			return nil, err
		}
	}

	pr := &Reader{
		deadline:    time.Time{},
		rings:       rings,
		poller:      poller,
		epollEvents: make([]unix.EpollEvent, len(rings)),
		epollRings:  make([]*EventRing, 0, len(rings)),
	}

	runtime.SetFinalizer(pr, (*Reader).Close)
	return pr, nil
}

func (pr *Reader) Close() error {
	if err := pr.poller.Close(); err != nil {
		if errors.Is(err, ErrClosed) {
			return nil
		}
		return fmt.Errorf("close poller: %w", err)
	}

	for _, ring := range pr.rings {
		if ring != nil {
			ring.Close()
		}
	}
	pr.rings = nil

	return nil
}

func (pr *Reader) SetDeadline(t time.Time) {
	pr.deadline = t
}

func (pr *Reader) GetDeadline() time.Time {
	return pr.deadline
}

type EventCb func(rd io.Reader, data interface{}, cpu int) error

func (pr *Reader) ReadData(cb EventCb, data interface{}) error {
	if pr.rings == nil {
		return fmt.Errorf("perf ringbuffer: %w", ErrClosed)
	}

	for {
		if len(pr.epollRings) == 0 {
			nEvents, err := pr.poller.Wait(pr.epollEvents, pr.deadline)
			if err != nil {
				return err
			}

			for _, event := range pr.epollEvents[:nEvents] {
				ring := pr.rings[cpuForEvent(&event)]
				pr.epollRings = append(pr.epollRings, ring)

				// Read the current head pointer now, not every time
				// we read a record. This prevents a single fast producer
				// from keeping the reader busy.
				ring.LoadHead()
			}
		}

		// Start at the last available event. The order in which we
		// process them doesn't matter, and starting at the back allows
		// resizing epollRings to keep track of processed rings.
		err := pr.readRecordFromRing(cb, data, pr.epollRings[len(pr.epollRings)-1])
		if err == ErrEOR {
			// We've emptied the current ring buffer, process
			// the next one.
			pr.epollRings = pr.epollRings[:len(pr.epollRings)-1]
			continue
		}

		return err
	}
}

func cpuForEvent(event *unix.EpollEvent) int {
	return int(event.Pad)
}

// NB: Has to be preceded by a call to ring.LoadHead.
func (pr *Reader) readRecordFromRing(cb EventCb, data interface{}, ring *EventRing) error {
	defer ring.WriteTail()

	return cb(ring, data, ring.Cpu)
}

func (pr *Reader) GetFDs() []int {
	var fds []int

	for _, ring := range pr.rings {
		fds = append(fds, ring.Fd)
	}

	return fds
}
