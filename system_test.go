package gold

import (
	"bytes"
	"encoding/json"
	// "io/ioutil"
	"net/http"
	// "net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// func TestSPKAC(t *testing.T) {
// 	spkac := `MIICRTCCAS0wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDK/2gvbZk5wajwkX6wwhCrG39NetMycseg8nFgN23MKSLbjU/JspvCrk6jlHNs8d1+FcFyU/AHqYYiY60mSMymDetnho/iqW5sThziyOaVmQ7I7JM6Lqr1tD3376VTvq/1KKrIJrnyCEuxeysflFpS+uTY5X5YV5n8AUPQhjr0aJXnIAI0SryLd0KeSGb+p7uxlmKG7Q8mxl1wel3WXEFr1oVLa61BHfbO8IhrAV8bUBsc0tWX/OSZc611exX1XZ/f3ujxRaL96xraN7AS7/zNI024r4261jPnVTpdFwf2CcnfU7rwCjgcezfBDcIVOUliyUfh1QTRZEYS4LUUVHAHAgMBAAEWBWhlbGxvMA0GCSqGSIb3DQEBBAUAA4IBAQCIBcbE+nw/vpjLvdl7EVnX4TWpKxDej92MOafyaOjNmy/iVhto57Lr+jBhm0A1oHpmGXLarkQPSLcXndZJFm/WSdHZ5pids+fEpe9yyMhgYYkVqqNbnGQmgSrmRZjIbzF6J69SaYXqJ1jQAZ4RrxRsgimfUfGw3C59yytdqkqllg2ojZe158vRlO/X6ysyCevchT9InDAWXE8YM/LBaI6jSlAz1BUFw0phpnAWTpULjMoP45QelY26gfNT1oDD+7PXAiEeo101kba67UcKXr8/7Z05iUONvkE+X1nNLynpvSskz7hha0pjtR+ipDVL9vIQxBFZ1xwrbbOj1fmIKzaE`
// 	response, _ := http.PostForm(testServer.URL+"/,system/spkac",
// 		url.Values{"spkac": {spkac},
// 			"username": {"user"},
// 			"name":     {"Test User"},
// 			"email":    {"test@user.org"},
// 			"img":      {"https://img.org/"},
// 		})
// 	body, _ := ioutil.ReadAll(response.Body)
// 	response.Body.Close()
// 	println(body)
// 	//assert.Equal(t, 200, response.StatusCode)
// }

func TestAccountStatus(t *testing.T) {
	ar := accountRequest{
		Method:      "accountStatus",
		AccountName: "deiu",
	}
	jsonData, err := json.Marshal(ar)
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", testServer.URL+"/,system/accountStatus", bytes.NewReader(jsonData))
	assert.NoError(t, err)
	response, err := user1h.Do(request)
	assert.NoError(t, err)
	response.Body.Close()
	assert.Equal(t, 200, response.StatusCode)
}
