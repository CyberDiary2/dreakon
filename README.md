# dreakon

wildcard domain recon tool - find every endpoint for a target domain.

## what it does

runs a full 5-phase recon pipeline:

1. **subdomain enumeration:** passive OSINT (crt.sh, shodan, virustotal, securitytrails, github, censys, wayback, urlscan) + dns brute force + permutation engine
2. **dns resolution:** resolves A/AAAA/CNAME/MX/TXT/NS/SRV/CAA records, wildcard detection, zone transfer attempts, subdomain takeover detection
3. **http probing:** probes 11 ports per host, captures redirect chains, TLS cert SANs, tech stack fingerprinting
4. **endpoint discovery:** BFS crawler, JS bundle analysis (webpack chunks, source maps), wayback/common crawl/otx history, openapi/graphql/wsdl discovery, tech-aware path fuzzing
5. **output:** JSONL (burp/nuclei compatible), nuclei targets list, markdown report

re-feed loops: new subdomains found in JS files or TLS cert SANs automatically trigger phases 2-4 for those hosts.

## install

```bash
git clone git@github.com:CyberDiary2/dreakon.git
cd dreakon
python -m venv venv
source venv/bin/activate
pip install -e .
```

**arch linux note:** do not use `playwright install --with-deps` - it tries to run apt-get and will fail. use:
```bash
playwright install chromium
```
playwright is only needed for JS-rendered page support (not yet active in current version).

## config

```bash
cp .env.example .env
```

edit `.env` and add api keys. all keys are optional - dreakon degrades gracefully without them, but more keys = more coverage:

| key | source | improves |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | virustotal.com | subdomain enumeration |
| `SECURITYTRAILS_API_KEY` | securitytrails.com | subdomain enumeration |
| `SHODAN_API_KEY` | shodan.io | subdomain + ip enumeration |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | censys.io | certificate enumeration |
| `GITHUB_TOKEN` | github.com/settings/tokens | finds internal subdomains in public code |
| `URLSCAN_API_KEY` | urlscan.io | endpoint discovery from page scans |

## usage

```bash
# full scan, results saved to current directory
dreakon scan example.com

# save everything to a folder (recommended)
dreakon scan example.com --output ./results/example

# skip fuzzing and brute force for a faster passive-only run
dreakon scan example.com --output ./results/example --no-fuzz --no-brute

# skip screenshots
dreakon scan example.com --output ./results/example --no-screenshots

# custom sqlite db path
dreakon scan example.com --db ./runs/example.db
```

## output files

each run produces the following in the output directory:

```
results/example/
├── screenshots/                          <- one png per live url, filename is the url
├── <domain>_<timestamp>_endpoints.jsonl
├── <domain>_<timestamp>_nuclei_targets.txt
└── <domain>_<timestamp>_report.md
```

- `endpoints.jsonl` - one endpoint per line, importable into burp suite or nuclei
- `nuclei_targets.txt` - plain url list, feed directly into nuclei:

```bash
nuclei -list results/example/<domain>_*_nuclei_targets.txt
```

- `report.md` - markdown report with subdomains, endpoints, and findings table
