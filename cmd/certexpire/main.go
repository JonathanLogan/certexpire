package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/JonathanLogan/certexpire"
)

var (
	configFile       string
	mailTemplateFile string
	timeout          int
	workers          int
	cache            bool
	debug            int
	verbose          int
	exthelp          bool
)

func init() {
	flag.StringVar(&mailTemplateFile, "m", "", "Mail message template file")
	flag.StringVar(&configFile, "c", "", "Check configuration file")
	flag.BoolVar(&cache, "s", true, "Use check cache")
	flag.IntVar(&timeout, "t", 10, "Check execution timeout")
	flag.IntVar(&workers, "w", 10, "Number of concurrent checks") // NUMPROCS
	flag.IntVar(&debug, "d", 1, "Debug level, max 2")
	flag.IntVar(&verbose, "v", 1, "Verbosity level, max 2")
	flag.BoolVar(&exthelp, "extended-help", false, "Print the extended help")
	flag.Parse()

	if exthelp {
		printNewHelp()
	}
}

func main() {

	report := &certexpire.Report{
		Workers:  workers,
		Timeout:  time.Second * time.Duration(timeout),
		UseCache: cache,
		Logger:   certexpire.NewLogger(2, 2),
	}

	if mailTemplateFile != "" {
		mailTemplate, err := ioutil.ReadFile(mailTemplateFile)
		if err != nil {
			report.Logger.Log(certexpire.MsgError, err.Error())
			report.Logger.Stop()
			os.Exit(3)
		}
		report.MailTemplate = mailTemplate
	}

	if configFile == "" {
		report.Logger.Log(certexpire.MsgError, "No check configuration file given")
		report.Logger.Stop()
		os.Exit(3)
	}
	configFileD, err := ioutil.ReadFile(configFile)
	if err != nil {
		report.Logger.Log(certexpire.MsgError, err.Error())
		report.Logger.Stop()
		os.Exit(3)
	}
	report.Logger = certexpire.NewLogger(debug, verbose)
	config, errorList, err := certexpire.ParseConfig(string(configFileD))
	if err != nil {
		report.Logger.Log(certexpire.MsgError, strings.Join(errorList, "\n"))
		report.Logger.Stop()
		os.Exit(3)
	}

	report.Generate(config)

	os.Exit(report.Logger.Stop())
}

var newhelp = `# certexpire

certexpire is a tool to check the expiration date (NotAfter) and optionally the hash of x509 certificates.
These certificates can be loaded from file, the standard output of a program, or from the network.
Network protocols supported are direct TLS/SSL connections over TCP, as well as IMAP and SMTP with STARTTLS.

Certificate checks are defined in a configuration file that understand several commands.
Each line defines one command. Lines starting with # are comments.

== 
The standard test command looks like:
  hostname:param:protocol:deadline:<hash>

hostname refers both to network connection hostname as well as owner of certificate.
param refers to the parameter used for this check, it depends on the protocol. Supported protocols are:
  ssl or tls: Direct TLS/SSL connection over TCP. Param must contain the port number.
  imap: STARTTLS for IMAP. Param is the port number.
  smtp: STARTTLS for SMTP. Param is the port number.
  file: Load certificate from a file. Param is the path to the file.
  command: Load certificate from the standard output of a command. Param is the command to run.
deadline is the warning duration before certificate expiration. Understands s/m/d.
hash is optional, and is the sha512 hash of the certificate. Use certexpire with verbosity level 1 or over to
learn the hash.

==
certexpire can send warnings via email. The following line defines the outgoing email settings to use.
  =mailserver:port:from:username:password

mailserver is the SMTP server to connect to, at port.
from is the sender address for all emails.
username and password are used for authentication (only LOGIN is supported).

==
certexpire will send the warnings for checks only if a receiving email address is defined.
Checks apply to the closest previous receiving email address defined.

  @emailaddress

emailaddress is the address to send to.

==
certexpire also supports SOCKS5 connections for its checks. The setting applies to all following checks.

  !proxyaddress

proxyaddress is the hostname:port of a SOCKS5 server.
Set proxyaddress to "direct" to disable a previous proxy configuration.

==
The exit code of certexpire is meaningful. It returns:

 0 if no errors were encountered. Everything is a-okay.
 1 if at least one of the checks failed.
 2 if there was a processing error and a certificate could not be loaded.
 3 is only returned if there are errors in the check configuration file.

==
There are verbose and debug outputs. By default they are both 0 and as a consequence nothing is printed.

Verbosity levels:
  0  Print nothing
  1  Print errors from checks
  2  Print both errors and successes from checks

Debug levels:
  0  Print nothing
  1  Print processing and configuration errors
  2  Print processing and configuration errors as well as status messages

==
The template to generate emails can be changed. The default template is:

----- SNIP -----
From: <{{ .From }}>
To: <{{ .Report.MailTo }}>
Subject: SSL certificates check failed

The following servers have failed the TLS certificate check:
{{ range $e := .Report.Checks }}
{{- if or $e.Error $e.ExecuteError }}
{{ $e.Hostname }}:{{ $e.Param}} ({{$e.Protocol}}): Expires {{ $e.ExpireTime }}
{{ if $e.Error -}} {{- range $err := $e.Error }} ==> {{ $err}} {{- end}} {{- end}} 
{{ if $e.ExecuteError -}} ==> ({{$e.ExecuteError}}) {{- end -}} 
{{- end -}}
{{- end }}

Update ASAP!
----- SNIP -----

Data available for the check result are:
 Hostname,        string: Hostname for connect and certificate ownership.
 Param,           string: The parameter. Depends on protocol.
 Protocol,        string: The protocol (tls, imap, etc).
 Deadline, time.Duration: Warning deadline for expiration.
 Hash,            string: The expected/configured certificate hash.
 ReturnHash,      string: The actual hash returned by the check.
 Error,          []error: List of verification errors.
 ExecuteError,     error: If there was an error on retrieving the certificate.
 ExpireTime,   time.Time: The certificate's NotAfter.



==
Commandline parameters:

  -c string Check configuration file
            Define the file from which to load check configuration. Required.

  -d int    Debug level, max 2 (default 0)
  -v int    Verbosity level, max 2 (default 0)
  -extendend-help  Print the extended help (this!)
    	
  -m string Mail message template file
  			Define the file containing an alternative mail message template.

  -s	    Use check cache (default true)
            Cache duplicate certificate retrieval results.

  -t int    Check execution timeout (default 10)
            Timeout for a check to complete, or fail.

  -w int    Number of concurrent checks (default 10)
            Parallel checks are performed. Define how many may run in parallel.`

func printNewHelp() {
	fmt.Println(newhelp)
	os.Exit(0)
}
