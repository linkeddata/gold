package gold

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	handlerSmtp *Server
)

func init() {
	cfg := NewServerConfig()
	cfg.Root += "_test/"
	cfg.Vhosts = false
	cfg.Debug = true
	cfg.SMTPConfig = EmailConfig{
		Name: "Full Name",
		Addr: "email@example.org",
		User: "username",
		Pass: "password",
		Host: "mail.example.org",
		Port: 465,
	}
	handlerSmtp = NewServer(cfg)
}

func TestInitMail(t *testing.T) {
	assert.NotEmpty(t, handlerSmtp.Config.SMTPConfig)
	assert.NotEmpty(t, handlerSmtp.Config.SMTPConfig.Addr)
	assert.NotEmpty(t, handlerSmtp.Config.SMTPConfig.Host)
	assert.NotEmpty(t, handlerSmtp.Config.SMTPConfig.Name)
	assert.NotEmpty(t, handlerSmtp.Config.SMTPConfig.Pass)
	assert.NotEmpty(t, handlerSmtp.Config.SMTPConfig.Port)
	assert.NotEmpty(t, handlerSmtp.Config.SMTPConfig.User)
}
