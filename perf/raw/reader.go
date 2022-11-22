package raw

import (
	"errors"
	"os"
	"time"
)

var (
	ErrClosed = os.ErrClosed
	ErrEOR    = errors.New("end of ring")
)

type Reader struct {
	deadline time.Time
}

func NewReader() (*Reader, error) {
	pr := &Reader{
		deadline: time.Time{},
	}
	return pr, nil
}

func (pr *Reader) SetDeadline(t time.Time) {
	pr.deadline = t
}

func (pr *Reader) GetDeadline() time.Time {
	return pr.deadline
}
