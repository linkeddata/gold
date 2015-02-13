package gold

var (
	config  = NewServerConfig()
	handler *Server
)

func init() {
	config.Root = GetServerRoot()
	handler = NewServer(config)
}
