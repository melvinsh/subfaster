package runner

import (
	"bufio"
	"context"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"

	"github.com/melvinsh/subfaster/v2/pkg/passive"
	"github.com/melvinsh/subfaster/v2/pkg/resolve"
)

// Runner is an instance of the subdomain enumeration
// client used to orchestrate the whole process.
type Runner struct {
	options        *Options
	passiveAgent   *passive.Agent
	resolverClient *resolve.Resolver
}

// NewRunner creates a new runner struct instance by parsing
// the configuration options, configuring sources, reading lists
// and setting up loggers, etc.
func NewRunner(options *Options) (*Runner, error) {
	options.ConfigureOutput()
	runner := &Runner{options: options}

	// Check if the application loading with any provider configuration, then take it
	// Otherwise load the default provider config
	if fileutil.FileExists(options.ProviderConfig) {
		gologger.Info().Msgf("Loading provider config from %s", options.ProviderConfig)
		options.loadProvidersFrom(options.ProviderConfig)
	} else {
		gologger.Info().Msgf("Loading provider config from the default location: %s", defaultProviderConfigLocation)
		options.loadProvidersFrom(defaultProviderConfigLocation)
	}

	// Initialize the passive subdomain enumeration engine
	runner.initializePassiveEngine()

	// Initialize the subdomain resolver
	err := runner.initializeResolver()
	if err != nil {
		return nil, err
	}

	return runner, nil
}

// RunEnumerationWithCtx runs the subdomain enumeration flow on the targets specified
func (r *Runner) RunEnumerationWithCtx(ctx context.Context) error {
	outputs := []io.Writer{r.options.Output}

	if len(r.options.Domain) > 0 {
		domainsReader := strings.NewReader(strings.Join(r.options.Domain, "\n"))
		return r.EnumerateMultipleDomainsWithCtx(ctx, domainsReader, outputs)
	}

	// If we have multiple domains as input,
	if r.options.DomainsFile != "" {
		f, err := os.Open(r.options.DomainsFile)
		if err != nil {
			return err
		}
		err = r.EnumerateMultipleDomainsWithCtx(ctx, f, outputs)
		if closeErr := f.Close(); closeErr != nil {
			gologger.Error().Msgf("Error closing file %s: %s", r.options.DomainsFile, closeErr)
		}
		return err
	}

	// If we have STDIN input, treat it as multiple domains
	if r.options.Stdin {
		return r.EnumerateMultipleDomainsWithCtx(ctx, os.Stdin, outputs)
	}
	return nil
}

// EnumerateMultipleDomainsWithCtx enumerates subdomains for multiple domains
// We keep enumerating subdomains for a given domain until we reach an error
func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) error {
	var err error
	scanner := bufio.NewScanner(reader)
	ip, _ := regexp.Compile(`^([0-9\.]+$)`)
	for scanner.Scan() {
		domain := preprocessDomain(scanner.Text())
		domain = replacer.Replace(domain)

		if domain == "" || (r.options.ExcludeIps && ip.MatchString(domain)) {
			continue
		}

		var file *os.File
		// If the user has specified an output file, use that output file instead
		// of creating a new output file for each domain. Else create a new file
		// for each domain in the directory.
		if r.options.OutputFile != "" {
			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(r.options.OutputFile, true)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			_, err = r.EnumerateSingleDomainWithCtx(ctx, domain, append(writers, file))

			if closeErr := file.Close(); closeErr != nil {
				gologger.Error().Msgf("Error closing file %s: %s", r.options.OutputFile, closeErr)
			}
		} else if r.options.OutputDirectory != "" {
			outputFile := path.Join(r.options.OutputDirectory, domain)
			if r.options.JSON {
				outputFile += ".json"
			} else {
				outputFile += ".txt"
			}

			outputWriter := NewOutputWriter(r.options.JSON)
			file, err = outputWriter.createFile(outputFile, false)
			if err != nil {
				gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, r.options.Domain, err)
				return err
			}

			_, err = r.EnumerateSingleDomainWithCtx(ctx, domain, append(writers, file))

			if closeErr := file.Close(); closeErr != nil {
				gologger.Error().Msgf("Error closing file %s: %s", outputFile, closeErr)
			}
		} else {
			_, err = r.EnumerateSingleDomainWithCtx(ctx, domain, writers)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
