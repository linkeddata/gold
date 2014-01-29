package gold

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

type httpRequest http.Request
type Handler struct{ http.Handler }

func (h Handler) ServeHTTP(w http.ResponseWriter, req0 *http.Request) {
	var (
		data []byte
		req  = (*httpRequest)(req0)
	)

	defer func() {
		req.Body.Close()
	}()
	dataMime := req.Header.Get("Content-Type")
	dataMime = strings.Split(dataMime, ";")[0]
	dataParser := parserMime[dataMime]
	if len(dataMime) > 0 && len(dataParser) == 0 {
		w.WriteHeader(415)
		// TODO: RDF errors
		fmt.Fprintln(w, "Unsupported Media Type")
	} else if len(dataMime) > 0 {
		_, err := ioutil.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(400) // Bad Request
			fmt.Fprintln(w, err)
		}
	}

	acceptList, _ := req.Accept()
	cMime, err := acceptList.Negotiate(serializerMimes...)
	if err != nil {
		w.WriteHeader(406) // Not Acceptable
		fmt.Fprintln(w, err)
	}

	// fmt.Println(acceptList, cMime)
	log.Println(data)

	switch req.Method {
	case "GET", "HEAD", "OPTIONS":
		if req.Method != "GET" {
			w.WriteHeader(200)
			return
		}
		if cMime == "text/html" {
			w.WriteHeader(200)
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, tabulatorSkin)
			return
		}

	case "POST":
	case "PUT":
	case "DELETE":
	case "MKCOL":
	case "PATCH":
	}
	w.WriteHeader(405) // Method Not Allowed
	fmt.Fprintln(w, err)
}
