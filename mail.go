package certexpire

import (
	"bytes"
	"fmt"
	"net/smtp"
	"text/template"
)

type EmailData struct {
	From   string
	Report ConfigEntry
}

func (rep *Report) reportMsg(ce *EmailData) []byte {
	if rep.MailTemplate == nil {
		rep.MailTemplate = []byte(emailtmpl)
	}
	t, err := template.New("email").Parse(string(rep.MailTemplate))
	if err != nil {
		rep.Error(fmt.Sprintf("Email template: %s", err))
		return nil
	}
	wr := new(bytes.Buffer)
	err = t.Execute(wr, ce)
	if err != nil {
		rep.Error(fmt.Sprintf("Email template: %s", err))
		return nil
	}
	return wr.Bytes()
}

func (rep *Report) SendReport(ce ConfigEntry) {
	auth := smtp.PlainAuth("", rep.MailUsername, rep.MailPassword, rep.MailHostname)
	msg := rep.reportMsg(&EmailData{
		From:   rep.MailFrom,
		Report: ce,
	})
	if msg == nil {
		rep.Error(fmt.Sprintf("Email: %s", ce.MailTo))
		return
	}
	err := smtp.SendMail(rep.MailHostname+":"+rep.MailPort, auth, rep.MailFrom, []string{ce.MailTo}, msg)
	if err != nil {
		rep.Error(fmt.Sprintf("Email: %s", err))
	} else {
		rep.Status(fmt.Sprintf("Email to %s", ce.MailTo))
	}
}
