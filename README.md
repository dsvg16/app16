# Tatou

Tatou is a web platform for PDF watermarking. You upload a PDF, add a watermark that carries
a secret, and share a per-recipient version. If a copy leaks, you can read the watermark and
find out who leaked it.

This project is for a course and it contains security vulnerabilities on purpose. Do not run it
on an open network.

## Set up

All commands are for a bash terminal on Linux. Adapt them if you use something else.

```bash
# Clone your own fork of the repo, then:
cd tatou/server

# Make a virtual environment and activate it
python3 -m venv .venv
. .venv/bin/activate

# Install the project with its dev/test dependencies
python -m pip install -e ".[dev]"
```

## Run the unit tests

From `server/` with the virtual environment active:

```bash
python -m pytest
```

This runs the whole test suite (watermarking methods, helpers, and the routes).

## Run the API tests

The API tests go through the Flask routes using the test client. The main files are
`test/test_api.py`, `test/test_rmap_endpoints.py`, and `test/test_list_versions_routes.py`.
Routes that touch the database expect a MariaDB reachable through the `DB_*` environment
variables (this is the same database service our CI pipeline starts).

```bash
python -m pytest test/test_api.py test/test_rmap_endpoints.py test/test_list_versions_routes.py
```

## Coverage analysis

We measure branch coverage over the server source. Our CI pipeline fails the build if coverage
drops under 70%.

```bash
python -m pytest --cov=src --cov-branch --cov-report=term-missing --cov-report=html
```

`term-missing` prints the lines that are not covered. The browsable report is written to
`htmlcov/index.html`.

## Deploy

From the root of the repository:

```bash
# Copy the sample environment file and set your own passwords/keys in it
cp sample.env .env

# Build the images and start the containers (server + database + monitor)
docker compose up --build -d

# Watch the logs
docker compose logs -f

# Check the API is up
http -v :5000/healthz
```

Then open `127.0.0.1:5000` in a browser to see the web app.
