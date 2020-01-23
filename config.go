package certexpire

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

type ServerCheck struct {
	Hostname     string
	Param        string
	Protocol     string
	Deadline     time.Duration
	Hash         string
	ReturnHash   string
	Error        []error
	ExecuteError error
	ExpireTime   time.Time
	Proxy        *Proxy
	KeyS, KeyC   int // used internally
}

type Proxy struct {
	Server string
}

func ParseProxyLine(l string) *Proxy {
	l = cleanline(l)
	if len(l) == 0 || l == "direct" {
		return nil
	}
	return &Proxy{
		Server: l,
	}
}

func (sc ServerCheck) Copy() ServerCheck {
	return sc
}

func cleanline(s string) string {
	return strings.ToLower(strings.TrimFunc(s, unicode.IsSpace))
}

func ParseServerLine(l string) (*ServerCheck, error) {
	var err error
	// hostname:port:proto:deadline
	fs := strings.Split(l, ":")
	if len(fs) < 4 || len(fs) > 5 {
		return nil, errors.New("format error")
	}
	sc := &ServerCheck{
		Hostname: cleanline(fs[0]),
		Param:    cleanline(fs[1]),
		Protocol: cleanline(fs[2]),
	}
	sc.Deadline, err = ParseDuration(cleanline(fs[3]))
	if err != nil {
		return nil, err
	}
	switch sc.Protocol {
	case "ssl", "tls", "imap", "smtp", "file", "command":
		break
	default:
		return nil, errors.New("unknown protocol")
	}
	if len(fs) == 5 {
		sc.Hash = cleanline(fs[4])
	}
	return sc, nil
}

type SMTPConfig struct {
	Hostname string
	Port     string
	From     string
	Username string
	Password string
}

func (sc *SMTPConfig) Copy() *SMTPConfig {
	return &SMTPConfig{
		Hostname: sc.Hostname,
		Port:     sc.Port,
		From:     sc.From,
		Username: sc.Username,
		Password: sc.Password,
	}
}

func ParseSMTPLine(l string) (*SMTPConfig, error) {
	// =hostname:port:from:"username":"password"
	fs := strings.Split(l, ":")
	if len(fs) != 5 {
		return nil, errors.New("format error")
	}
	sc := &SMTPConfig{
		Hostname: cleanline(fs[0]),
		Port:     cleanline(fs[1]),
		From:     cleanline(fs[2]),
		Username: strings.TrimFunc(fs[3], unicode.IsSpace),
		Password: strings.TrimFunc(fs[4], unicode.IsSpace),
	}
	return sc, nil
}

type ConfigEntry struct {
	MailTo    string
	NumChecks int
	Alert     bool
	Checks    []ServerCheck
}

type Config struct {
	Tests []ConfigEntry
	Mail  *SMTPConfig
}

func removeComment(s string) string {
	p := strings.IndexByte(s, '#')
	if p >= 0 {
		return s[p:]
	}
	return s
}

func ParseConfig(l string) (*Config, []string, error) {
	var hasMail bool
	var proxy *Proxy
	ret := &Config{
		Tests: make([]ConfigEntry, 0, 1),
	}
	errorList := make([]string, 0, 0)
	lines := strings.Split(l, "\n")
LineLoop:
	for i, l := range lines {
		l = strings.TrimFunc(removeComment(l), unicode.IsSpace)
		if len(l) == 0 {
			continue LineLoop
		}
		if len(l) < 2 {
			errorList = append(errorList, fmt.Sprintf("Parse error line %d: short line", i+1))
			continue LineLoop
		}
		if l[0] == '!' {
			proxy = ParseProxyLine(l[1:])
			continue LineLoop
		}
		if l[0] == '=' {
			c, err := ParseSMTPLine(l[1:])
			if err != nil {
				errorList = append(errorList, fmt.Sprintf("Parse error line %d: %s", i+1, err))
				continue LineLoop
			}
			ret.Mail = c
			continue LineLoop
		}
		if l[0] == '@' {
			hasMail = true
			ret.Tests = append(ret.Tests, ConfigEntry{
				MailTo: cleanline(l[1:]),
				Checks: make([]ServerCheck, 0, 1),
			})
			continue LineLoop
		}
		if !hasMail {
			ret.Tests = append(ret.Tests, ConfigEntry{
				Checks: make([]ServerCheck, 0, 1),
			})
			hasMail = true
		}
		sl, err := ParseServerLine(l)
		if err != nil {
			errorList = append(errorList, fmt.Sprintf("Parse error line %d: %s", i+1, err))
			continue LineLoop
		}
		sl.Proxy = proxy
		sl.KeyS = len(ret.Tests) - 1
		sl.KeyC = len(ret.Tests[len(ret.Tests)-1].Checks)
		ret.Tests[len(ret.Tests)-1].Checks = append(ret.Tests[len(ret.Tests)-1].Checks, *sl)
	}
	for i := 0; i < len(ret.Tests); i++ {
		ret.Tests[i].NumChecks = len(ret.Tests[i].Checks)
	}
	if len(errorList) > 0 {
		return nil, errorList, errors.New("Parse error")
	}
	return ret, nil, nil
}
