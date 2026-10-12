package runner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

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

	lastAgent  atomic.Pointer[passive.Agent] // most recently finished domain, for GetStatistics
	callbackMu sync.Mutex                    // one ResultCallback at a time across domains
	outputMu   sync.Mutex                    // keeps per-domain output and stats tables whole
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

// EnumerateMultipleDomainsWithCtx enumerates subdomains for multiple domains,
// up to Options.Threads at a time. Each domain's results are written as one
// sorted block, in input order. It stops at the first output error.
func (r *Runner) EnumerateMultipleDomainsWithCtx(ctx context.Context, reader io.Reader, writers []io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type job struct {
		domain string
		out    bytes.Buffer
		done   chan struct{}
	}
	workers := max(r.options.Threads, 1)
	slots := make(chan struct{}, workers)
	// Jobs queue here in input order; the writer below waits for each in turn.
	pending := make(chan *job, workers)

	// Live "FAST" animation on stderr for the whole batch (no-op when not a
	// TTY). Only in the default silent mode: log lines would fight the redrawn line.
	var first string
	var started, finished atomic.Int64
	var meter *speedometer
	if r.options.Silent && !r.options.Verbose {
		meter = newSpeedometer(func() string {
			switch n := started.Load(); n {
			case 0:
				return ""
			case 1:
				return first // written before started was incremented
			default:
				return fmt.Sprintf("%d/%d domains", finished.Load(), n)
			}
		})
		meter.start()
		defer meter.Stop()
	}

	var writeErr error
	written := make(chan struct{})
	go func() {
		defer close(written)
		for j := range pending {
			<-j.done
			if writeErr == nil {
				if writeErr = r.writeDomainOutput(j.domain, j.out.Bytes(), writers, meter); writeErr != nil {
					cancel()
				}
			}
		}
	}()

	scanner := bufio.NewScanner(reader)
	ip, _ := regexp.Compile(`^([0-9\.]+$)`)
scan:
	for scanner.Scan() {
		domain := preprocessDomain(scanner.Text())
		domain = replacer.Replace(domain)

		if domain == "" || (r.options.ExcludeIps && ip.MatchString(domain)) {
			continue
		}

		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			break scan
		}
		j := &job{domain: domain, done: make(chan struct{})}
		if started.Load() == 0 {
			first = domain
		}
		started.Add(1)
		pending <- j
		go func() {
			defer func() {
				finished.Add(1)
				close(j.done)
				<-slots
			}()
			// Writes to a bytes.Buffer can't fail, so there is no error to handle.
			_, _ = r.enumerateDomain(ctx, j.domain, []io.Writer{&j.out}, meter)
		}()
	}
	close(pending)
	<-written

	if writeErr != nil {
		return writeErr
	}
	return scanner.Err()
}

// writeDomainOutput writes one domain's results to writers and, with -o or
// -oD, to the output file.
func (r *Runner) writeDomainOutput(domain string, data []byte, writers []io.Writer, meter *speedometer) error {
	var file *os.File
	var err error
	// If the user has specified an output file, use that output file instead
	// of creating a new output file for each domain. Else create a new file
	// for each domain in the directory.
	if r.options.OutputFile != "" {
		file, err = NewOutputWriter(r.options.JSON).createFile(r.options.OutputFile, true)
		if err != nil {
			gologger.Error().Msgf("Could not create file %s for %s: %s\n", r.options.OutputFile, domain, err)
			return err
		}
	} else if r.options.OutputDirectory != "" {
		outputFile := path.Join(r.options.OutputDirectory, domain)
		if r.options.JSON {
			outputFile += ".json"
		} else {
			outputFile += ".txt"
		}
		file, err = NewOutputWriter(r.options.JSON).createFile(outputFile, false)
		if err != nil {
			gologger.Error().Msgf("Could not create file %s for %s: %s\n", outputFile, domain, err)
			return err
		}
	}
	if file != nil {
		writers = append(writers, file)
		defer func() {
			if closeErr := file.Close(); closeErr != nil {
				gologger.Error().Msgf("Error closing file %s: %s", file.Name(), closeErr)
			}
		}()
	}

	r.outputMu.Lock()
	defer r.outputMu.Unlock()
	meter.Print(func() {
		for _, writer := range writers {
			if writer == nil {
				continue
			}
			if _, err = writer.Write(data); err != nil {
				gologger.Error().Msgf("Could not write results for %s: %s\n", domain, err)
				return
			}
		}
	})
	return err
}
