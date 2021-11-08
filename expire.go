package certexpire

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os/exec"
	"time"
)

// // TLSTimeout is timeout for negotiating a TLS connection.
// var TLSTimeout = time.Second * 10

func deadline(timeout time.Duration) time.Time {
	return time.Now().Add(timeout)
}

// CertValues contains the relevant aspects of a certificate.
type CertValues struct {
	Hostname    string    // Hostname used for retrieval connection.
	Expire      time.Time // Time this certificate expires.
	VerifyError error     // Any TLS  errors when connecting.
	Hash        string    // Hash of the raw certificate.
	Certificate *x509.Certificate
}

func hashString(d []byte) string {
	return fmt.Sprintf("%x", sha512.Sum512(d))
}

func convertCertificate(hostname string, cert *x509.Certificate, prevError ...error) *CertValues {
	ret := &CertValues{
		Hostname:    hostname,
		Expire:      cert.NotAfter,
		Hash:        hashString(cert.Raw),
		Certificate: cert,
	}
	if hostname != "" {
		ret.VerifyError = cert.VerifyHostname(hostname)
	}
	if ret.VerifyError == nil && len(prevError) > 0 {
		ret.VerifyError = prevError[0]
	}
	return ret
}

// GetCertificate returns the server certificate's expiry time. conn is an established connection. hostname is the hostname of the remote server.
func GetCertificate(conn net.Conn, hostname string, timeout time.Duration) (*CertValues, error) {
	c := tls.Client(conn, &tls.Config{ServerName: hostname, InsecureSkipVerify: true})
	defer c.Close()
	_ = c.SetDeadline(deadline(timeout))
	err := c.Handshake()
	if err != nil {
		return &CertValues{
			Hostname:    hostname,
			VerifyError: err,
		}, nil
	}
	state := c.ConnectionState()

	certs := state.PeerCertificates
	if len(certs) == 0 {
		return &CertValues{
			Hostname: hostname,
		}, ErrNoCert
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return convertCertificate(hostname, certs[0], err), nil
	}
	return convertCertificate(hostname, certs[0]), nil
}

func verifyPEM(servername string, d []byte) (*CertValues, error) {
	block, _ := pem.Decode(d)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return &CertValues{
			Hostname: servername,
		}, ErrNoCert
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &CertValues{
			Hostname: servername,
		}, ErrNoCert
	}
	return convertCertificate(servername, cert), nil
}

// GetCertFile verifies a file
func GetCertFile(servername, path string) (*CertValues, error) {
	d, err := ioutil.ReadFile(path)
	if err != nil {
		return &CertValues{
			Hostname: servername,
		}, err
	}
	return verifyPEM(servername, d)
}

// GetCertCMD runs a command and interpretes the standard output as a certificate.
func GetCertCMD(servername, command string, timeout time.Duration) (*CertValues, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	d, err := exec.CommandContext(ctx, command).Output()
	if err != nil {
		return &CertValues{
			Hostname: servername,
		}, err
	}
	return verifyPEM(servername, d)
}

// GetCertTLS returns the server certificate's expiry time for a TLS server.
func GetCertTLS(servername, port string, timeout time.Duration, proxy *Proxy) (*CertValues, error) {
	conn, err := TCPDailer(servername+":"+port, proxy, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(deadline(timeout))
	return GetCertificate(conn, servername, timeout)
}

// GetCert returns the server certificate's expiry time. Proto is tls/ssl, imap, smtp.
func GetCert(servername, param, proto string, timeout time.Duration, proxy *Proxy) (*CertValues, error) {
	switch proto {
	case "tls", "ssl", "":
		return GetCertTLS(servername, param, timeout, proxy)
	case "imap":
		return GetCertIMAP(servername, param, timeout, proxy)
	case "smtp":
		return GetCertSMTP(servername, param, timeout, proxy)
	case "file":
		return GetCertFile(servername, param)
	case "command":
		return GetCertCMD(servername, param, timeout)
	default:
		return nil, ErrConfig
	}
}
