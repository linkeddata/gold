package gold

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Generated using:
//   openssl spkac -key privkey.pem -challenge hello -out spkac.cnf
var spkacRSABase64 = `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`

func TestParseSPKAC(t *testing.T) {
	derBytes, _ := base64.StdEncoding.DecodeString(spkacRSABase64)
	_, err := ParseSPKAC(derBytes)
	assert.NoError(t, err)
}

func TestCreateCertificateFromSPKAC(t *testing.T) {
	uri := "https://example.org/person/card#me"
	name := "User Test"

	newSpkac, err := NewSPKACx509(uri, name, spkacRSABase64)
	assert.NoError(t, err)

	certParsed, err := x509.ParseCertificate(newSpkac)
	assert.NoError(t, err)

	for _, x := range certParsed.Extensions {
		if x.Id.Equal(subjectAltName) {
			v := asn1.RawValue{}
			_, err = asn1.Unmarshal(x.Value, &v)
			assert.NoError(t, err)
			assert.Equal(t, uri, string(v.Bytes[2:]))
		}
	}

}
