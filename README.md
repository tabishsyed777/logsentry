# LogSentry

> Authentication signal, clarified.

LogSentry now includes a static dashboard that runs entirely in the browser and can be hosted on GitHub Pages. Open `index.html` locally or publish the repository with the included Pages workflow. The browser interface accepts Common or Combined Log Format files, detects repeated authentication failures, and exports a JSON report without uploading log data.

LogSentry is a small, local-first security project for learning how to spot suspicious authentication activity in web server logs. It reads a supplied access log, counts failed login attempts by source IP, and writes a concise JSON report. It does not scan networks, contact external services, or block traffic.

## Browser dashboard

The dashboard is the easiest way to explore the project:

1. Open `index.html`, or enable GitHub Pages from the repository's **Settings → Pages** using GitHub Actions.
2. Load the included sample or drop in an authorized `.log` file.
3. Adjust the failure threshold and rolling window, then select **Analyze source**.
4. Export the report when you need to share the result.

The interface is deliberately dependency-free so it works on a static GitHub Pages host.

## Run the analyzer with Docker

Start Docker Desktop, then from this directory run:

```sh
docker build -t logsentry .
docker run --rm -v "$PWD/samples:/data:ro" -v "$PWD/reports:/reports" logsentry /data/access.log --output /reports/report.json
```

The sample log is synthetic. The report is written to `reports/report.json` on your computer.

## Run without Docker

Requires Python 3.11 or newer:

```sh
python3 logsentry.py samples/access.log --output reports/report.json
```

## Detection logic

The tool parses the common/combined web log format, selects failed responses (401 or 403) for likely authentication paths, and flags IPs meeting the configurable threshold in the selected time window. The default threshold is 5 failures within 10 minutes. This is a learning heuristic, not an intrusion-detection system: proxies, shared networks, malformed logs, and normal user mistakes can affect results.

```sh
python3 logsentry.py samples/access.log --threshold 3 --window-minutes 15
```

## Report fields

- `generated_at`: UTC timestamp when the report was created
- `source_file`: input file name
- `summary`: parsed lines, authentication failures, and flagged sources
- `alerts`: source IP, failure count, time span, and representative paths

## Safety and privacy

Use only logs you are authorized to analyze. Logs can contain IP addresses and URL data; keep reports private and remove them when no longer needed. The container runs as an unprivileged user and receives the sample directory read-only.

## Project structure

```text
.
├── Dockerfile
├── index.html
├── styles.css
├── app.js
├── logsentry.py
├── samples/access.log
├── .github/workflows/pages.yml
└── reports/.gitkeep
```

## Ideas for extending it

- Add CSV output and a summary table
- Compare multiple time windows to reduce noisy alerts
- Add unit tests for log parsing and threshold boundaries
- Import JSON logs from a local application

## License

MIT. See [LICENSE](LICENSE).

