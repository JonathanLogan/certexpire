package certexpire

import (
	"fmt"
	"os"
	"strings"
)

const (
	MsgError     = 0
	MsgStatus    = 1
	MsgLogError  = 2
	MsgLogStatus = 3
)

type Logger struct {
	debug, verbose int
	msgChan        chan interface{}
	done           chan int
}

type LogLine struct {
	MsgType int
	Message string
}

func NewLogger(debug, verbose int) *Logger {
	l := &Logger{
		debug:   debug,
		verbose: verbose,
		msgChan: make(chan interface{}, 10),
		done:    make(chan int, 1),
	}
	go func() {
		var cerr, perr bool
		for m := range l.msgChan {
			switch e := m.(type) {
			case LogLine:
				switch e.MsgType {
				case MsgError:
					perr = true
					if l.debug > 0 {
						fmt.Fprintf(os.Stderr, "Err: %s\n", e.Message)
					}
				case MsgStatus:
					if l.debug > 1 {
						fmt.Fprintf(os.Stderr, "Log: %s\n", e.Message)
					}
				case MsgLogError:
					cerr = true
					if l.verbose > 0 {
						fmt.Fprintf(os.Stdout, "Err,%s\n", e.Message)
					}
				case MsgLogStatus:
					if l.verbose > 1 {
						fmt.Fprintf(os.Stdout, "Log,%s\n", e.Message)
					}
				}
			default:
				if perr {
					l.done <- 2
				} else if cerr {
					l.done <- 1
				} else {
					l.done <- 0
				}
				close(l.done)
			}
		}
	}()
	return l
}

func (l *Logger) Log(msgType int, msg string) {
	l.msgChan <- LogLine{
		MsgType: msgType,
		Message: msg,
	}
}

func (l *Logger) Stop() int {
	l.msgChan <- struct{}{}
	r := <-l.done
	return r
}

func (rep *Report) Error(err string) {
	rep.Logger.Log(MsgError, err)
}

func (rep *Report) Status(s string) {
	rep.Logger.Log(MsgStatus, s)
}

func (rep *Report) LogStatus(sc *ServerCheck) {
	rep.Logger.Log(MsgLogStatus, fmt.Sprintf("%s:%s", sc.Hostname, sc.Param))
}

func (rep *Report) LogError(sc *ServerCheck) {
	var errors []string
	var extra string
	for _, l := range sc.Error {
		if l == ErrHash {
			extra += fmt.Sprintf(",Hash=%s", sc.ReturnHash)
		}
		if l == ErrExpire {
			extra += fmt.Sprintf(",Expires=%s", sc.ExpireTime.Format("2006-02-01"))
		}
		errors = append(errors, l.Error())
	}
	if sc.ExecuteError != nil {
		errors = append(errors, sc.ExecuteError.Error())
	}
	rep.Logger.Log(MsgLogError, fmt.Sprintf("%s:%s,[\"%s\"]%s", sc.Hostname, sc.Param, strings.Join(errors, "\", \""), extra))
}
