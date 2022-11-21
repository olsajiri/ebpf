package raw

type Reader struct {
}

func NewReader() (*Reader, error) {
	pr := &Reader{}
	return pr, nil
}
