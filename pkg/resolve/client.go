package resolve

import (
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// DefaultResolvers contains the default list of resolvers known to be good.
// Cloudflare only — fast and reliable; system resolvers are usually slow.
var DefaultResolvers = []string{
	"1.1.1.1:53", // Cloudflare primary
	"1.0.0.1:53", // Cloudflare secondary
}

// Resolver is a struct for resolving DNS names
type Resolver struct {
	DNSClient *dnsx.DNSX
}

// New creates a new resolver struct
func New() *Resolver {
	return &Resolver{}
}
