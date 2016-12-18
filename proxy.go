package gold

import (
	"github.com/solid/solidproxy"
)

var (
	proxyService *solidproxy.Proxy
	agentService *solidproxy.Agent
)

func init() {
	// init with an empty agent (public)
	agentService = &solidproxy.Agent{}
	proxyService = solidproxy.NewProxy(agentService, true)
}

func SetProxyService(proxy *solidproxy.Proxy) {
	proxyService = proxy
}

func SetAgentService(agent *solidproxy.Agent) {
	agentService = agent
	// reinit the proxy with the new agent
	proxyService = solidproxy.NewProxy(agent, true)
}
