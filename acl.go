package gold

var (
	ACLSuffix = ",acl"
)

type WAC struct {
	req  *httpRequest
	srv  *Server
	user string
}

func NewWAC(req *httpRequest, srv *Server, user string) *WAC {
	return &WAC{req: req, srv: srv, user: user}
}

func (acl *WAC) AllowRead() bool {
	return true
}

func (acl *WAC) AllowWrite() bool {
	return true
}

func (acl *WAC) AllowAppend() bool {
	return true
}
