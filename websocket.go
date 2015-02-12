package gold

import (
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/websocket"
)

func websocketHandler(ws *websocket.Conn) {
	// echo server
	log.Println(io.Copy(ws, ws))
}

func websocketServe(w http.ResponseWriter, req *http.Request) {
	websocket.Handler(websocketHandler).ServeHTTP(w, req)
}

func websocketUpgrade(r *http.Request) bool {
	if r == nil {
		return false
	}
	if strings.ToLower(r.Header.Get("Connection")) != "upgrade" {
		return false
	}
	if strings.ToLower(r.Header.Get("Upgrade")) != "websocket" {
		return false
	}
	return true
}
