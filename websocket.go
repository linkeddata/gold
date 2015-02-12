package gold

import (
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/websocket"
)

// Handles each websocket connection
func websocketHandler(ws *websocket.Conn) {
	log.Println(io.Copy(ws, ws))
}

// Converts an HTTP request to a websocket server
func websocketServe(w http.ResponseWriter, req *http.Request) {
	websocket.Handler(websocketHandler).ServeHTTP(w, req)
}

// Checks whether an HTTP request looks like websocket
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
