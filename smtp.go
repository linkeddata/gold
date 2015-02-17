package gold

import (
	"bytes"
	"net/smtp"
	"strconv"
	"text/template"
)

type EmailConfig struct {
	Name string
	Addr string
	User string
	Pass string
	Host string
	Port int
}

type SMTPTemplateData struct {
	From    string
	To      string
	Subject string
	Body    string
}

// should be ran in a go routine
func (s *Server) sendMail(goldHost string, to []string, msg string, tpl string) {
	smtpCfg := &s.Config.SMTPConfig
	context := &SMTPTemplateData{
		smtpCfg.Name,
		to[0],
		"Recovery instructions for your account on " + goldHost,
		msg,
	}
	t := template.New(tpl)
	t, err := t.Parse(SMTPTemplates[tpl])
	if err != nil {
		s.debug.Println("Error trying to parse mail template")
	}
	var body bytes.Buffer
	err = t.Execute(&body, context)
	if err != nil {
		s.debug.Println("Error trying to execute mail template")
	}

	auth := smtp.PlainAuth("",
		smtpCfg.User,
		smtpCfg.Pass,
		smtpCfg.Host,
	)

	if len(smtpCfg.Host) > 0 && smtpCfg.Port > 0 {
		smtpServer := smtpCfg.Host + ":" + strconv.Itoa(smtpCfg.Port)
		err = smtp.SendMail(smtpServer, auth, smtpCfg.Addr, to, body.Bytes())
		if err != nil {
			println(err.Error())
			s.debug.Println("Error sending email to " + to[0] + ": " + err.Error())
		}
	} else {
		s.debug.Println("Missing smtp server and/or port")
	}
}
