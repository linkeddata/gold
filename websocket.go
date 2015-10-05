package gold

import (
	"io"
	"log"
	"net/http"
	"strings"
	"sync"

	"golang.org/x/net/websocket"
)

// type wsConn struct {
// 	subbed bool
// 	uuid   string
// }

var (
	websocketSubs  = map[string]map[*websocket.Conn]string{}
	websocketSubsL = new(sync.RWMutex)
)

func onDeleteURI(uri string) {
	websocketPublish(uri)
}

func onUpdateURI(uri string) {
	websocketPublish(uri)
}

// Handles each websocket connection
func websocketHandler(ws *websocket.Conn) {
	// @@TODO switch to server logging
	// log.Println("opened via:", ws.RemoteAddr())

	uris := map[string]bool{}
	message := ""
	for {
		err := websocket.Message.Receive(ws, &message)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Println(err)
			break
		}

		argv := strings.Split(message, " ")
		if len(argv) < 2 {
			argv = append(argv, "")
		}

		cmd, uri := argv[0], argv[1]
		switch cmd {

		case "ping":
			websocket.Message.Send(ws, "pong")

		case "sub":
			uris[uri] = true
			websocketSubsL.Lock()
			if _, ex := websocketSubs[uri]; !ex {
				websocketSubs[uri] = map[*websocket.Conn]string{}
			}
			websocketSubs[uri][ws] = NewUUID()
			websocketSubsL.Unlock()
			websocket.Message.Send(ws, "ack "+uri)

		case "unsub":
			websocketSubsL.Lock()
			uris[uri] = false
			if len(websocketSubs[uri][ws]) > 0 {
				delete(websocketSubs[uri], ws)
			}
			websocketSubsL.Unlock()
			websocket.Message.Send(ws, "removed "+uri)

		default:
			log.Println("invalid message:", message)
		}
	}

	websocketSubsL.Lock()
	for k := range uris {
		delete(websocketSubs[k], ws)
	}
	websocketSubsL.Unlock()
	// @@TODO switch to server logging
	// log.Println("closed via:", ws.RemoteAddr())
}

func websocketPublish(uri string, uuid ...string) {
	websocketSubsL.RLock()
	subs := websocketSubs[uri]
	websocketSubsL.RUnlock()

	for k := range subs {
		uuidMatch := true
		// log.Println(uuid)
		if len(uuid) > 0 && subs[k] != uuid[0] {
			uuidMatch = false
		}
		if uuidMatch {
			err := websocket.Message.Send(k, "pub "+uri)
			if err != nil {
				log.Println(err)
			}
		}
	}
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
