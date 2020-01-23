package certexpire

import (
	"bytes"
	"net"
	"time"
)

func imapHasStartTLS(m []byte) bool {
	match := []byte("STARTTLS")
	s := bytes.IndexByte(m, '[')
	if s < 0 {
		return false
	}
	e := bytes.IndexByte(m[s:], ']')
	if e < 0 {
		return false
	}
	fs := bytes.Fields(m[s+1 : s+e])
	for _, f := range fs {
		if bytes.Equal(f, match) {
			return true
		}
	}
	return false
}

func imapprelude(conn net.Conn) error {
	r := NewLineReader(conn)
	l, err := r.Line()
	if err != nil {
		return err
	}
	if !bytes.Equal(l[0:4], []byte("* OK")) {
		return ErrProtocol
	}
	if !imapHasStartTLS(l[4:]) {
		return ErrProtocol
	}
	_, err = conn.Write([]byte("001 STARTTLS\r\n"))
	if err != nil {
		return err
	}
	l, err = r.Line()
	if err != nil {
		return err
	}
	if bytes.Index(l, []byte("001 OK")) < 0 {
		return ErrProtocol
	}
	return nil
}

// GetCertIMAP returns the expiration date of an IMAP STARTTLS cert.
func GetCertIMAP(servername, port string, timeout time.Duration, proxy *Proxy) (*CertValues, error) {
	conn, err := TCPDailer(servername+":"+port, proxy, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(deadline(timeout))
	defer conn.Close()
	if err := imapprelude(conn); err != nil {
		return nil, err
	}
	return GetCertificate(conn, servername, timeout)
}
