package certexpire

import (
	"sync"
	"time"

	"github.com/gammazero/workerpool"
)

type Report struct {
	Workers      int
	Timeout      time.Duration
	UseCache     bool
	Logger       *Logger
	MailTemplate []byte

	cache *Cache

	MailHostname string
	MailPort     string
	MailFrom     string
	MailUsername string
	MailPassword string
}

func (rep *Report) Generate(config *Config) {
	if config.Mail != nil {
		rep.MailHostname = config.Mail.Hostname
		rep.MailPort = config.Mail.Port
		rep.MailFrom = config.Mail.From
		rep.MailUsername = config.Mail.Username
		rep.MailPassword = config.Mail.Password
	}

	if rep.cache == nil {
		rep.cache = NewCache()
	}
	mailRoutines := new(sync.WaitGroup)
	endChan := make(chan interface{}, 1)
	resultChan := make(chan interface{}, rep.Workers)
	pool := workerpool.New(rep.Workers)
	go func() {
		for m := range resultChan {
			switch e := m.(type) {
			case bool:
				close(endChan)
				return
			case *ServerCheck:
				config.Tests[e.KeyS].NumChecks--
				config.Tests[e.KeyS].Checks[e.KeyC] = *e
				if e.Error != nil || e.ExecuteError != nil {
					config.Tests[e.KeyS].Alert = true
					rep.LogError(e)
					if e.ExecuteError != nil {
						rep.Error(e.ExecuteError.Error())
					}
				} else {
					rep.LogStatus(e)
				}
				if config.Mail != nil &&
					config.Tests[e.KeyS].Alert &&
					config.Tests[e.KeyS].MailTo != "" &&
					config.Tests[e.KeyS].NumChecks <= 0 {

					mailRoutines.Add(1)
					go func() {
						defer mailRoutines.Done()
						rep.SendReport(config.Tests[e.KeyS])
					}()
				}
			}
		}
	}()
	for _, e := range config.Tests {
		for _, c := range e.Checks {
			x := c.Copy()
			pool.Submit(func() {
				rep.VerifyCert(&x, rep.Timeout)
				resultChan <- &x
			})
		}
	}
	pool.StopWait()
	resultChan <- false
	<-endChan
	mailRoutines.Wait()
}

type getCertResult struct {
	certValues *CertValues
	err        error
}

func getCertFuture(servername, port, proto string, timeout time.Duration, proxy *Proxy) *getCertResult {
	r := &getCertResult{}
	r.certValues, r.err = GetCert(servername, port, proto, timeout, proxy)
	return r
}

func getCertCacheKey(servername, port, proto string) string {
	return servername + ":" + port + "/" + proto
}

func (rep *Report) GetCert(servername, port, proto string, timeout time.Duration, proxy *Proxy) (*CertValues, error) {
	c := rep.cache.Lookup(getCertCacheKey(servername, port, proto), func() interface{} { return getCertFuture(servername, port, proto, timeout, proxy) })
	r := <-c
	rt := r.(*getCertResult)
	return rt.certValues, rt.err
}

func (rep *Report) VerifyCert(sc *ServerCheck, timeout time.Duration) error {
	var cv *CertValues
	var err error
	sc.Error = make([]error, 0, 1)
	if rep.UseCache {
		cv, err = rep.GetCert(sc.Hostname, sc.Param, sc.Protocol, timeout, sc.Proxy)
	} else {
		cv, err = GetCert(sc.Hostname, sc.Param, sc.Protocol, timeout, sc.Proxy)
	}
	if err != nil {
		sc.ExecuteError = err
		return err
	}
	sc.ExpireTime = cv.Expire
	if cv.VerifyError != nil {
		sc.Error = append(sc.Error, cv.VerifyError)
	}
	sc.ReturnHash = cv.Hash
	if sc.Hash != "" && cv.Hash != sc.Hash {
		sc.Error = append(sc.Error, ErrHash)
	}
	if time.Now().Add(sc.Deadline).After(cv.Expire) {
		sc.Error = append(sc.Error, ErrExpire)
	}
	if len(sc.Error) == 0 {
		sc.Error = nil
	}
	return nil
}
