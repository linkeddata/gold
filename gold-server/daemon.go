package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/fcgi"

	"github.com/linkeddata/gold"
)

var (
	bind = flag.String("bind", "", "bind address (empty: fcgi)")
)

func init() {
	flag.Parse()
}

func main() {
	var err error

	handler := gold.Handler{}
	if bind == nil || len(*bind) == 0 {
		err = fcgi.Serve(nil, handler)
	} else {
		err = http.ListenAndServe(*bind, handler)
	}
	if err != nil {
		log.Fatal(err)
	}
}
