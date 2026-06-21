package runner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/melvinsh/subfaster/v2/pkg/passive"
	"github.com/melvinsh/subfaster/v2/pkg/resolve"
	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
	"github.com/projectdiscovery/chaos-client/pkg/chaos"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	envutil "github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
	logutil "github.com/projectdiscovery/utils/log"
	updateutils "github.com/projectdiscovery/utils/update"
)

var (
	configDir                     = folderutil.AppConfigDirOrDefault(".", "subfaster")
	defaultConfigLocation         = envutil.GetEnvOrDefault("SUBFASTER_CONFIG", filepath.Join(configDir, "config.yaml"))
	defaultProviderConfigLocation = envutil.GetEnvOrDefault("SUBFASTER_PROVIDER_CONFIG", filepath.Join(configDir, "provider-config.yaml"))
)

// Options contains the configuration options for tuning
// the subdomain enumeration process.
type Options struct {
	Verbose            bool                // Verbose flag indicates whether to show verbose output or not
	NoColor            bool                // NoColor disables the colored output
	JSON               bool                // JSON specifies whether to use json for output format or text file
	HostIP             bool                // HostIP specifies whether to write subdomains in host:ip format
	Silent             bool                // Silent suppresses any extra text and only writes subdomains to screen
	ListSources        bool                // ListSources specifies whether to list all available sources
	RemoveWildcard     bool                // RemoveWildcard specifies whether to remove potential wildcard or dead subdomains from the results.
	CaptureSources     bool                // CaptureSources specifies whether to save all sources that returned a specific domains or just the first source
	Stdin              bool                // Stdin specifies whether stdin input was given to the process
	Version            bool                // Version specifies if we should just show version and exit
	OnlyRecursive      bool                // Recursive specifies whether to use only recursive subdomain enumeration sources
	All                bool                // All specifies whether to use all (slow) sources.
	Fast               bool                // Fast restricts enumeration to the curated fast keyless sources
	Statistics         bool                // Statistics specifies whether to report source statistics
	Threads            int                 // Threads controls the number of threads to use for active enumerations
	Timeout            int                 // Timeout is the seconds to wait for sources to respond
	MaxEnumerationTime int                 // MaxEnumerationTime is the maximum amount of time in minutes to wait for enumeration
	Domain             goflags.StringSlice // Domain is the domain to find subdomains for
	DomainsFile        string              // DomainsFile is the file containing list of domains to find subdomains for
	Output             io.Writer
	OutputFile         string              // Output is the file to write found subdomains to.
	OutputDirectory    string              // OutputDirectory is the directory to write results to in case list of domains is given
	Sources            goflags.StringSlice `yaml:"sources,omitempty"`         // Sources contains a comma-separated list of sources to use for enumeration
	ExcludeSources     goflags.StringSlice `yaml:"exclude-sources,omitempty"` // ExcludeSources contains the comma-separated sources to not include in the enumeration process
	Resolvers          goflags.StringSlice `yaml:"resolvers,omitempty"`       // Resolvers is the comma-separated resolvers to use for enumeration
	ResolverList       string              // ResolverList is a text file containing list of resolvers to use for enumeration
	Config             string              // Config contains the location of the config file
	ProviderConfig     string              // ProviderConfig contains the location of the provider config file
	Proxy              string              // HTTP proxy
	ExcludeIps         bool
	Match              goflags.StringSlice
	Filter             goflags.StringSlice
	matchRegexes       []*regexp.Regexp
	filterRegexes      []*regexp.Regexp
	ResultCallback     OnResultCallback // OnResult callback
	DisableUpdateCheck bool             // DisableUpdateCheck disable update checking
}

// OnResultCallback (hostResult)
type OnResultCallback func(result *resolve.HostEntry)

// ParseOptions parses the command line flags provided by a user
func ParseOptions() *Options {
	logutil.DisableDefaultLogger()

	options := &Options{}

	var err error
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Subfaster - fast passive subdomain discovery (a speed-focused fork of subfinder).`)

	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Domain, "domain", "d", nil, "target domain(s) to enumerate (-d example.com,acme.com)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.DomainsFile, "list", "dL", "", "file with target domains, one per line"),
	)

	flagSet.CreateGroup("source", "Sources",
		flagSet.BoolVar(&options.Fast, "fast", true, "curated fast keyless sources only - default; -all for everything"),
		flagSet.BoolVar(&options.All, "all", false, "use every source (slow; many need API keys)"),
		flagSet.StringSliceVarP(&options.Sources, "sources", "s", nil, "use only these sources (-s crtsh,virustotal)", goflags.NormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.ExcludeSources, "exclude-sources", "es", nil, "skip these sources (-es alienvault)", goflags.NormalizedStringSliceOptions),
		flagSet.BoolVar(&options.OnlyRecursive, "recursive", false, "only sources that support recursive enumeration"),
		flagSet.BoolVarP(&options.ListSources, "list-sources", "ls", false, "list all available sources and exit"),
	)

	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "write results to file"),
		flagSet.BoolVarP(&options.JSON, "json", "oJ", false, "write results as JSON lines"),
		flagSet.StringVarP(&options.OutputDirectory, "output-dir", "oD", "", "write per-domain files to dir (with -dL)"),
		flagSet.BoolVarP(&options.CaptureSources, "collect-sources", "cs", false, "include the source name(s) per subdomain (with -oJ)"),
	)

	flagSet.CreateGroup("active", "Active resolution",
		flagSet.BoolVarP(&options.RemoveWildcard, "active", "nW", false, "resolve subdomains and keep only live ones"),
		flagSet.BoolVarP(&options.HostIP, "ip", "oI", false, "include the resolved IP in output (with -active)"),
		flagSet.StringSliceVar(&options.Resolvers, "r", nil, "resolvers to use (comma-separated)", goflags.NormalizedStringSliceOptions),
		flagSet.StringVarP(&options.ResolverList, "rlist", "rL", "", "file with resolvers to use"),
		flagSet.IntVar(&options.Threads, "t", 10, "concurrent resolver threads (with -active)"),
	)

	flagSet.CreateGroup("filter", "Filter",
		flagSet.StringSliceVarP(&options.Match, "match", "m", nil, "keep only subdomains matching (file or comma-separated)", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Filter, "filter", "f", nil, "drop subdomains matching (file or comma-separated)", goflags.FileNormalizedStringSliceOptions),
	)

	flagSet.CreateGroup("configuration", "Configuration",
		flagSet.StringVarP(&options.ProviderConfig, "provider-config", "pc", defaultProviderConfigLocation, "provider/API-key config file"),
		flagSet.StringVar(&options.Config, "config", defaultConfigLocation, "config file"),
		flagSet.StringVar(&options.Proxy, "proxy", "", "HTTP proxy URL"),
		flagSet.BoolVarP(&options.ExcludeIps, "exclude-ip", "ei", false, "skip IP addresses in the input"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "per-source timeout in seconds"),
		flagSet.IntVar(&options.MaxEnumerationTime, "max-time", 10, "max enumeration time in minutes"),
	)

	flagSet.CreateGroup("debug", "Output control",
		flagSet.BoolVar(&options.Silent, "silent", true, "print only subdomains - default; -silent=false or -v for logs"),
		flagSet.BoolVar(&options.Verbose, "v", false, "verbose logging"),
		flagSet.BoolVarP(&options.NoColor, "no-color", "nc", false, "disable colored output"),
		flagSet.BoolVar(&options.Statistics, "stats", false, "print per-source stats at the end"),
		flagSet.BoolVar(&options.Version, "version", false, "print version and exit"),
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update subfaster to the latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", true, "skip the update check - default; -duc=false to enable"),
	)

	flagSet.SetCustomHelpText(`EXAMPLES:
  Enumerate one domain:
    subfaster -d example.com

  Many domains from a file, saved to out.txt:
    subfaster -dL domains.txt -o out.txt

  Resolve and keep only live subdomains, with their IPs:
    subfaster -d example.com -active -oI

  Use every source (needs API keys in the provider config):
    subfaster -d example.com -all

  JSON output including which source found each subdomain:
    subfaster -d example.com -oJ -cs`)

	if err := flagSet.Parse(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// set chaos mode
	chaos.IsSDK = false

	if exists := fileutil.FileExists(defaultProviderConfigLocation); !exists {
		if err := createProviderConfigYAML(defaultProviderConfigLocation); err != nil {
			gologger.Error().Msgf("Could not create provider config file: %s\n", err)
		}
	}

	if options.Config != defaultConfigLocation {
		// An empty source file is not a fatal error
		if err := flagSet.MergeConfigFile(options.Config); err != nil && !errors.Is(err, io.EOF) {
			gologger.Fatal().Msgf("Could not read config: %s\n", err)
		}
	}

	// Default output is stdout
	options.Output = os.Stdout

	// Check if stdin pipe was given
	options.Stdin = fileutil.HasStdin()

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		gologger.Info().Msgf("Subfaster Config Directory: %s", configDir)
		os.Exit(0)
	}

	options.preProcessDomains()

	options.ConfigureOutput()

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("subfaster", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("subfaster version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current subfaster version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if options.ListSources {
		listSources(options)
		os.Exit(0)
	}

	// Validate the options passed by the user and if any
	// invalid options have been used, exit.
	err = options.validateOptions()
	if err != nil {
		gologger.Fatal().Msgf("Program exiting: %s\n", err)
	}

	return options
}

// loadProvidersFrom runs the app with source config
func (options *Options) loadProvidersFrom(location string) {
	// todo: move elsewhere
	if len(options.Resolvers) == 0 {
		options.Resolvers = resolve.DefaultResolvers
	}

	// We skip bailing out if file doesn't exist because we'll create it
	// at the end of options parsing from default via goflags.
	if err := UnmarshalFrom(location); err != nil && (!strings.Contains(err.Error(), "file doesn't exist") || errors.Is(err, os.ErrNotExist)) {
		gologger.Error().Msgf("Could not read providers from %s: %s\n", location, err)
	}
}

func listSources(options *Options) {
	gologger.Info().Msgf("Current list of available sources. [%d]\n", len(passive.AllSources))
	gologger.Info().Msgf("Sources marked with an * require key(s) or token(s) to work.\n")
	gologger.Info().Msgf("Sources marked with a ~ optionally support key(s) for better results.\n")
	gologger.Info().Msgf("You can modify %s to configure your keys/tokens.\n\n", options.ProviderConfig)

	for _, source := range passive.AllSources {
		sourceName := source.Name()
		switch source.KeyRequirement() {
		case subscraping.RequiredKey:
			gologger.Silent().Msgf("%s *\n", sourceName)
		case subscraping.OptionalKey:
			gologger.Silent().Msgf("%s ~\n", sourceName)
		default:
			gologger.Silent().Msgf("%s\n", sourceName)
		}
	}
}

func (options *Options) preProcessDomains() {
	for i, domain := range options.Domain {
		options.Domain[i] = preprocessDomain(domain)
	}
}
