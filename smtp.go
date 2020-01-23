package certexpire

import (
	"net"
	"os"
	"strings"
	"time"
)

func smtpHasStartTLS(s []string) bool {
	for _, l := range s {
		if strings.Index(l, "STARTTLS") >= 0 {
			return true
		}
	}
	return false
}

func smtpprelude(conn net.Conn) error {
	r := NewLineReader(conn)
	c, _, err := r.ReadNumericContinuous()
	if c != "220" {
		return ErrProtocol
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "local"
	}
	_, err = conn.Write([]byte("EHLO " + hostname + "\r\n"))
	if err != nil {
		return err
	}
	c, m, err := r.ReadNumericContinuous()
	if c != "250" {
		return ErrProtocol
	}
	if !smtpHasStartTLS(m) {
		return ErrProtocol
	}
	_, err = conn.Write([]byte("STARTTLS\r\n"))
	if err != nil {
		return err
	}
	c, _, err = r.ReadNumericContinuous()
	if c != "220" {
		return ErrProtocol
	}
	return nil
}

// GetCertSMTP returns the expiration date of an SMTP STARTTLS cert.
func GetCertSMTP(servername, port string, timeout time.Duration, proxy *Proxy) (*CertValues, error) {
	conn, err := TCPDailer(servername+":"+port, proxy, timeout)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(deadline(timeout))
	defer conn.Close()
	if err := smtpprelude(conn); err != nil {
		return nil, err
	}
	return GetCertificate(conn, servername, timeout)
}
