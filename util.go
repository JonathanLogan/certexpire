package certexpire

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"unicode"
)

var (
	ErrProtocol = errors.New("certexpire: protocol error")
	ErrNoCert   = errors.New("certexpire: no certificate")
	ErrConfig   = errors.New("certexpire: configuration error")
	ErrHash     = errors.New("Hash does not match")
	ErrExpire   = errors.New("Expiration warning")
)

// LineReader helps with dealing with text protocols on the network.
type LineReader struct {
	r *bufio.Reader
}

// NewLineReader returns r as a LineReader
func NewLineReader(r io.Reader) *LineReader {
	return &LineReader{r: bufio.NewReader(
		&io.LimitedReader{
			R: r,
			N: 8192,
		})}
}

// Line returns the next newline terminated line.
func (lr LineReader) Line() ([]byte, error) {
	return lr.r.ReadBytes(byte('\n'))
}

// ReadNumeric reads SMTP-like text protocol lines. Code contains the numeric code, if any.
// message contains the remainder of the line.
// cont signals if more lines should be read.
func (lr LineReader) ReadNumeric() (code, message string, cont bool, err error) {
	var c []byte
	s, err := lr.Line()
	if err != nil {
		return "", "", false, err
	}
	x := bytes.IndexFunc(s, func(r rune) bool { return !unicode.IsNumber(r) })
	if x > 0 {
		c = s[0:x]
		if len(s) > x+1 {
			if s[x] == '-' {
				cont = true
			}
			s = s[x+1:]
		}
	}
	return string(c), string(s), cont, nil
}

// ReadNumericContinuous continues to read until the server expects a message.
func (lr LineReader) ReadNumericContinuous() (code string, messages []string, err error) {
	messages = make([]string, 0, 1)
ReadLoop:
	for {
		code, message, cont, err := lr.ReadNumeric()
		if err != nil {
			return "", messages, err
		}
		messages = append(messages, message)
		if cont {
			continue ReadLoop
		}
		return code, messages, nil
	}
}
