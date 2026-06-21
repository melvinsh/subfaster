package runner

import (
	"net"
	"strings"

	"github.com/melvinsh/subfaster/v2/pkg/passive"
	"github.com/melvinsh/subfaster/v2/pkg/resolve"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

// FastSources is the curated set of fast, productive keyless sources used by -fast.
var FastSources = []string{"thc", "submd", "shodanct", "rapiddns", "hackertarget", "sitedossier"}

// initializePassiveEngine creates the passive engine and loads sources etc
func (r *Runner) initializePassiveEngine() {
	sources, useAll := r.options.Sources, r.options.All
	// -fast (default on) restricts to the curated fast keyless sources, unless
	// the user explicitly widened the set with -all or -sources. -exclude-sources
	// is always honored.
	if r.options.Fast && len(sources) == 0 && !useAll {
		sources = FastSources
	}
	r.passiveAgent = passive.New(sources, r.options.ExcludeSources, useAll, r.options.OnlyRecursive)
}

// initializeResolver creates the resolver used to resolve the found subdomains
func (r *Runner) initializeResolver() error {
	var resolvers []string

	// If the file has been provided, read resolvers from the file
	if r.options.ResolverList != "" {
		var err error
		resolvers, err = loadFromFile(r.options.ResolverList)
		if err != nil {
			return err
		}
	}

	if len(r.options.Resolvers) > 0 {
		resolvers = append(resolvers, r.options.Resolvers...)
	} else {
		resolvers = append(resolvers, resolve.DefaultResolvers...)
	}

	// Add default 53 UDP port if missing
	for i, resolver := range resolvers {
		if !strings.Contains(resolver, ":") {
			resolvers[i] = net.JoinHostPort(resolver, "53")
		}
	}

	r.resolverClient = resolve.New()
	var err error
	r.resolverClient.DNSClient, err = dnsx.New(dnsx.Options{BaseResolvers: resolvers, MaxRetries: 5})
	if err != nil {
		return nil
	}

	return nil
}
