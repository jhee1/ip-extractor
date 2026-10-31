# IP Extractor

A small Python tool that analyzes SSH authentication logs, finds IP addresses with repeated failed logins (a simple brute-force detection rule) and enriches them with threat intelligence from AbuseIPDB.

Built as a learning project for SOC / blue-team work.

## What it does

1. Reads an auth log file.
2. Keeps only lines describing failed logins (`Failed password`, `Failed publickey`, `authentication failure`).
3. Extracts IPv4 addresses with a regex and validates them (each octet 0-255).
4. Counts failed attempts per IP and flags those at or above a threshold.
5. Skips private addresses (RFC 1918) and checks public ones in AbuseIPDB: abuse score, country, ISP, Tor exit node.
6. Writes the report to `alerts.txt`.

## Setup

```
pip install -r requirements.txt
```

Create a free account at abuseipdb.com, copy your API key and put it in a `.env` file (see `.env.example`):

```
ABUSEIPDB_KEY=your_key_here
```

The `.env` file is ignored by Git. Never commit your key.

## Usage

```
python IP_extract.py <log_file> <threshold>
```

Example:

```
python IP_extract.py auth_test.log 3
```

`auth_test.log` is a fictional sample log included for testing.

## Example output (`alerts.txt`)

```
ALERT: 185.220.101.4 --> failed attempts: 4 | abuse score: 100 | country: DE | ISP: Artikel10 e.V. | Tor: True```

## Notes

- Do not send IPs from real production or customer logs to external services unless your organization's policy allows it.
- The free AbuseIPDB plan has a daily request limit.
- The tool only reads logs and queries a reputation API. It does not scan or touch any remote system.

## Possible improvements

- Skip whitelisted addresses (e.g. public DNS providers)
- Use the `verbose` option of the API to show report categories
- Cache lookups to avoid checking the same IP twice
- Support more log formats
