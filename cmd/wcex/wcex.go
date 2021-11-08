package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/JonathanLogan/certexpire/cmd/wcex/stringduration"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/JonathanLogan/certexpire"
)

// -v verbose: Have output.
// -t duration: Grace time. Default 1 day.

// GetCert(servername, param(port,file), proto(imap,smtp,tls), time.Second*5, nil) (*CertValues, error)

var (
	warningTime time.Duration
	warningTimeString string
	verbose     bool
)

func parseURL(s string) (servername, param, proto string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", "", "", err
	}
	switch u.Scheme {
	case "":
		return "", u.Path, "file", nil
	case "file":
		return "", u.Host + u.Path, "file", nil
	default:
		return u.Hostname(), u.Port(), u.Scheme, nil
	}
}

func init() {
	flag.StringVar(&warningTimeString, "t", "1d", "Warning time")
	flag.BoolVar(&verbose, "v", false, "Verbose")
}

func verboseInfo(status string, value *certexpire.CertValues) {
	if verbose {
		s := make([]string, 1, len(value.Certificate.DNSNames)+1)
		s[0] = value.Certificate.Subject.CommonName
		s = append(s, value.Certificate.DNSNames...)
		x := strings.Join(s, " ")
		_, _ = fmt.Fprintf(os.Stdout, "%s %d %s\n", status, value.Expire.Unix(), x)
	}
}

func main() {
	flag.Parse()
	warningTime,err:=stringduration.Parse(warningTimeString)
	if err!=nil{
		_,_=fmt.Fprintf(os.Stderr,"Bad value for warning time (-t): %s\n",warningTimeString)
		os.Exit(3)
	}
	args := flag.Args()
	if len(args) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "Error, missing subject. file/url (tls://,smtp://,imap://")
		os.Exit(3)
	}
	host, param, proto, err := parseURL(args[0])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error parsing subject: %s\n", err)
		os.Exit(3)
	}
	cert, err := certexpire.GetCert(host, param, proto, time.Second*5, nil)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error fetching certificate: %s\n", err)
		os.Exit(2)
	}
	if cert.VerifyError != nil {
		if err, ok := cert.VerifyError.(x509.CertificateInvalidError); ok {
			if err.Reason == x509.Expired {
				verboseInfo("expired", cert)
				os.Exit(0)
			}
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "Certificate validation: %s\n", cert.VerifyError)
			os.Exit(2)
		}
	}
	if cert.Expire.Before(time.Now().Add(warningTime)) {
		verboseInfo("expired", cert)
		os.Exit(0)
	}
	verboseInfo("valid", cert)
	os.Exit(1)
}
