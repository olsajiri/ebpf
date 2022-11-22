package raw

import "time"

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
