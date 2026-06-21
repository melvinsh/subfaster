<h1 align="center">subfaster</h1>

<h4 align="center">Fast passive subdomain enumeration — a speed-focused fork of <a href="https://github.com/projectdiscovery/subfinder">subfinder</a>.</h4>

---

`subfaster` is a fork of [subfinder](https://github.com/projectdiscovery/subfinder) tuned for one thing: getting a clean, sorted list of subdomains as fast as possible. It keeps subfinder's passive-source engine but changes the defaults, trims the startup cost, and drops weight so a typical run finishes in seconds with no noise.

It installs as its **own binary** with its **own config directory**, so it runs side by side with an existing `subfinder` install without colliding.

## What's different from subfinder

### Faster by default
- **Curated fast sources are the default.** A run uses six fast, keyless sources (`thc`, `submd`, `shodanct`, `rapiddns`, `hackertarget`, `sitedossier`) instead of every source. Use `-all` for the full set, or `-fast=false` for subfinder's original default selection.
- **HTTP keep-alive.** Connections are reused instead of a fresh TCP+TLS handshake per request. Sources that paginate heavily (e.g. `thc`) drop from ~32s to ~11s on large domains.
- **Update check is off by default.** subfinder makes a blocking network call to its update registry on every startup (~1s). subfaster skips it, so startup is ~30ms. Re-enable with `-duc=false`.
- **Lower default timeout** (10s, was 30s) and **Cloudflare-only resolvers** (`1.1.1.1`, `1.0.0.1`) for `-active`, instead of a long list that includes slow resolvers.
- **Preflight probe on block-prone sources.** `sitedossier` and `hackertarget` are checked with a cheap 3s homepage probe first — if your IP is blocked they bail in 3s instead of hanging the whole run to the timeout.

### Quieter, cleaner output
- **`-silent` is the default** — only subdomains go to stdout. Pass `-v` (or `-silent=false`) for logs.
- **Output is sorted alphabetically.**
- **No ASCII banner.**
- **Reorganized, terse `-h`** with examples, grouped by importance.
- **Honest source errors.** When a free source hits its quota (`hackertarget`) or a captcha (`sitedossier`), it's reported as an error in `-stats` instead of silently returning zero.

### Removed / changed
- **No rate-limit flags.** `-rl` / `-rls` and the rate-limiting engine are gone.
- **`crtsh` is HTTP/JSON only.** The crt.sh Postgres backend (and its driver dependency) was removed.
- **Fixed User-Agent** instead of a random one per request.

### Slimmer
Dropped direct dependencies: `json-iterator/go` (→ stdlib `encoding/json`), `lib/pq`, `corpix/uarand`, `rs/xid`, `hako/durafmt`, `golang.org/x/exp`, and the rate-limit library.

## Installation

`subfaster` requires **go1.24+**:

```sh
go install -v github.com/melvinsh/subfaster/v2/cmd/subfaster@latest
```

## Usage

```sh
subfaster -h
```

Common examples:

```sh
# Enumerate one domain (fast sources, only subdomains printed)
subfaster -d example.com

# Many domains from a file, saved to out.txt
subfaster -dL domains.txt -o out.txt

# Resolve and keep only live subdomains, with their IPs
subfaster -d example.com -active -oI

# Use every source (many need API keys, see below)
subfaster -d example.com -all

# JSON output including which source found each subdomain
subfaster -d example.com -oJ -cs
```

Run `subfaster -h` for the full, grouped flag list.

## Configuration

subfaster keeps its own config so it never clashes with subfinder:

- Config directory: `$HOME/.config/subfaster/` (`config.yaml`, `provider-config.yaml`)
- Environment overrides: `SUBFASTER_CONFIG`, `SUBFASTER_PROVIDER_CONFIG`
- API keys can also be supplied via `<SOURCE>_API_KEY` environment variables (e.g. `SHODAN_API_KEY`).

Many sources (used with `-all`) require API keys. The `provider-config.yaml` format is identical to subfinder's — see the upstream [post-install configuration docs](https://docs.projectdiscovery.io/tools/subfinder/install#post-install-configuration).

## Go library

subfaster can be used as a library; a minimal example is in [`examples/main.go`](examples/main.go).

## Credits

subfaster is a fork of [subfinder](https://github.com/projectdiscovery/subfinder) by [ProjectDiscovery](https://projectdiscovery.io) — all credit for the original tool and its source integrations goes to them and the upstream community ([THANKS.md](https://github.com/projectdiscovery/subfinder/blob/main/THANKS.md)).

Read the usage disclaimer at [DISCLAIMER.md](https://github.com/projectdiscovery/subfinder/blob/main/DISCLAIMER.md).
