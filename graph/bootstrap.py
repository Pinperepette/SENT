from __future__ import annotations

"""
Graph bootstrap — seed the dependency graph with top packages.

Without a pre-populated graph, cascade weights are useless:
we'd never know that urllib3 is critical because we haven't
seen requests yet.

Strategy:
  1. Fetch top N packages by download count (from PyPI stats / npm API)
  2. For each, fetch dependencies
  3. Build the graph
  4. Compute cascade weights
  5. Persist to DB

This runs once at startup or on demand. Takes ~2-5 minutes for 500 packages.
After that, the graph is incrementally updated as we ingest releases.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from graph.dependency_graph import graph

# Top PyPI packages by download (hardcoded seed — avoids BigQuery dependency).
# Source: https://hugovk.github.io/top-pypi-packages/
# These are the top ~200 most-downloaded PyPI packages.
# In production, fetch this from pypistats.org or BigQuery.
TOP_PYPI = [
    "boto3", "botocore", "urllib3", "requests", "setuptools",
    "certifi", "charset-normalizer", "idna", "pip", "python-dateutil",
    "typing-extensions", "s3transfer", "packaging", "six", "numpy",
    "pyyaml", "cryptography", "jmespath", "pyasn1", "cffi",
    "pycparser", "attrs", "platformdirs", "wheel", "filelock",
    "tomli", "importlib-metadata", "zipp", "virtualenv", "pluggy",
    "pyparsing", "pytz", "jinja2", "markupsafe", "colorama",
    "click", "pydantic", "awscli", "docutils", "rsa",
    "pandas", "protobuf", "jsonschema", "grpcio", "scipy",
    "pygments", "decorator", "pillow", "pyjwt", "wrapt",
    "google-api-core", "cachetools", "google-auth", "pyarrow",
    "pydantic-core", "annotated-types", "fsspec", "tqdm",
    "google-cloud-storage", "soupsieve", "beautifulsoup4", "aiohttp",
    "frozenlist", "aiosignal", "multidict", "yarl", "async-timeout",
    "distlib", "exceptiongroup", "sniffio", "anyio", "httpcore",
    "httpx", "h11", "rich", "markdown-it-py", "mdurl",
    "psutil", "lxml", "openpyxl", "et-xmlfile", "sqlalchemy",
    "greenlet", "matplotlib", "scikit-learn", "joblib", "threadpoolctl",
    "flask", "werkzeug", "itsdangerous", "gunicorn", "uvicorn",
    "starlette", "fastapi", "pynacl", "paramiko", "bcrypt",
    "tomlkit", "poetry-core", "dulwich", "black", "mypy-extensions",
    "pathspec", "isort", "pytest", "iniconfig", "coverage",
    "networkx", "sympy", "mpmath", "torch", "transformers",
    "tokenizers", "huggingface-hub", "safetensors", "regex", "sentencepiece",
    "celery", "kombu", "billiard", "amqp", "vine",
    "redis", "pymongo", "psycopg2-binary", "django", "djangorestframework",
    "connexion", "swagger-ui-bundle", "openapi-spec-validator",
    "alembic", "mako", "greenlet", "sqlparse",
    "docker", "websocket-client", "kubernetes", "google-auth-oauthlib",
    "grpcio-status", "google-cloud-core", "google-resumable-media",
    "google-api-python-client", "google-auth-httplib2", "httplib2",
    "oauth2client", "pyopenssl", "service-identity",
    "twisted", "automat", "hyperlink", "incremental",
    "scrapy", "parsel", "w3lib", "queuelib",
    "ansible", "ansible-core", "jinja2", "resolvelib",
    "sentry-sdk", "datadog", "newrelic", "opentelemetry-api",
    "anthropic", "openai", "tiktoken", "langchain", "langchain-core",
]

TOP_NPM = [
    "lodash", "chalk", "react", "express", "commander",
    "debug", "glob", "mkdirp", "minimist", "semver",
    "async", "moment", "request", "bluebird", "underscore",
    "uuid", "yargs", "fs-extra", "colors", "rimraf",
    "body-parser", "through2", "shelljs", "inquirer", "readable-stream",
    "cheerio", "webpack", "axios", "typescript", "eslint",
    "babel-core", "react-dom", "prop-types", "classnames", "jquery",
    "rxjs", "tslib", "zone.js", "core-js", "regenerator-runtime",
    "next", "vue", "angular", "svelte", "preact",
    "socket.io", "mongoose", "sequelize", "pg", "redis",
]

PYPI_JSON = "https://pypi.org/pypi/{name}/json"
NPM_REGISTRY = "https://registry.npmjs.org/{name}"


def _fetch_pypi_pkg(name: str) -> tuple:
    """Fetch a single PyPI package's deps and real downloads. Returns (name, deps, downloads)."""
    import re
    try:
        # Metadata + deps
        resp = httpx.get(PYPI_JSON.format(name=name), timeout=10, follow_redirects=True)
        if resp.status_code != 200:
            return (name, [], 0)
        data = resp.json()
        info = data.get("info", {})

        deps = []
        for req in (info.get("requires_dist") or []):
            dep = re.split(r'[><=!;\s\[]', req)[0].strip().lower()
            if dep:
                deps.append(dep)

        # Real downloads from pypistats.org
        downloads = 0
        try:
            stats = httpx.get(
                f"https://pypistats.org/api/packages/{name}/recent",
                timeout=5, follow_redirects=True,
            )
            if stats.status_code == 200:
                downloads = stats.json().get("data", {}).get("last_month", 0)
        except Exception:
            pass

        # Fallback
        if downloads <= 0:
            releases = len(data.get("releases", {}))
            downloads = max(releases * 100, 1000)

        return (name, deps, downloads)
    except Exception:
        return (name, [], 0)


def _fetch_npm_pkg(name: str) -> tuple:
    """Fetch a single npm package's deps. Returns (name, deps, downloads)."""
    try:
        resp = httpx.get(NPM_REGISTRY.format(name=name), timeout=10, follow_redirects=True)
        if resp.status_code != 200:
            return (name, [], 0)
        data = resp.json()
        latest = data.get("dist-tags", {}).get("latest", "")
        latest_info = data.get("versions", {}).get(latest, {})
        deps = list((latest_info.get("dependencies") or {}).keys())
        versions = len(data.get("versions", {}))
        downloads = max(versions * 200, 1000)
        return (name, deps, downloads)
    except Exception:
        return (name, [], 0)


def bootstrap_graph(
    pypi_top: int = 150,
    npm_top: int = 50,
    workers: int = 20,
    verbose: bool = True,
):
    """
    Seed the dependency graph with top packages from PyPI and npm.

    Fetches package metadata in parallel, builds the graph,
    computes cascade weights, and persists to DB.
    """
    t_start = time.perf_counter()

    pypi_names = TOP_PYPI[:pypi_top]
    npm_names = TOP_NPM[:npm_top]

    if verbose:
        print(f"[bootstrap] Seeding graph: {len(pypi_names)} PyPI + {len(npm_names)} npm packages")
        print(f"[bootstrap] Fetching metadata with {workers} workers...")

    fetched = 0
    total_deps = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        # Submit all fetches
        futures = {}
        for name in pypi_names:
            futures[pool.submit(_fetch_pypi_pkg, name)] = ("pypi", name)
        for name in npm_names:
            futures[pool.submit(_fetch_npm_pkg, name)] = ("npm", name)

        for future in as_completed(futures):
            eco, _ = futures[future]
            try:
                name, deps, downloads = future.result()
                if deps or downloads:
                    graph.add_package(name, eco, deps, downloads)
                    fetched += 1
                    total_deps += len(deps)
            except Exception:
                pass

    elapsed = time.perf_counter() - t_start

    # Compute cascade weights
    graph._ensure_cascade()

    if verbose:
        print(f"[bootstrap] Done in {elapsed:.1f}s")
        print(f"[bootstrap] Graph: {graph.total_packages()} packages, "
              f"{graph.total_edges()} edges")
        print(f"[bootstrap] Fetched: {fetched} packages, {total_deps} dep links")

        # Show top 10 by cascade weight
        top = graph.top_by_cascade(10)
        if top:
            print(f"\n[bootstrap] Top 10 by cascade weight:")
            for i, p in enumerate(top, 1):
                cw = p['cascade_weight']
                own = p['own_downloads']
                deps = p['direct_dependents']
                amplification = cw / own if own > 0 else 0
                print(f"  {i:2d}. {p['ecosystem']}/{p['name']}"
                      f"  cascade={cw:>12,}  own={own:>8,}"
                      f"  dependents={deps:>4}  amplification={amplification:>6.0f}x")

    # Persist
    graph.save_to_db()

    return graph
