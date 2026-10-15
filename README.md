# hx-http-security-cli

**HTTP security header and TLS certificate audit** for authorized web assessments —
scoring, redirect chains, and direct socket inspection.

## Why this exists

Missing HSTS, weak CSP, and disclosure headers remain common findings. This CLI fetches
a URL (following redirects), runs a rule-based header audit with severity scoring, and
can inspect TLS certificates independently of HTTP. Use only on applications you are
authorized to test.

## Features

- `audit` — Security header rules (CSP, HSTS, clickjacking, referrer, permissions, etc.)
  with score /100
- `chain` — Redirect hop listing with final URL and status
- `tls` — Certificate subject, issuer, validity, SANs via direct TLS socket
- `--json` on all commands; exit `2` when audit score is below 70 or cert expires within
  14 days

## Install

```bash
git clone https://github.com/HackerX-official/hx-http-security-cli.git
cd hx-http-security-cli
npm install
npm run build
npm link   # optional: global hx-http
```

## Quick start

```bash
hx-http audit https://app.example.com
hx-http chain https://app.example.com --json
hx-http tls app.example.com -p 443 --json
```

## Output

| Mode     | Description                                                          |
| -------- | -------------------------------------------------------------------- |
| Default  | Colored severity lines per finding; TLS prints cert fields           |
| `--json` | `{ chain, audit }` for audit; redirect chain or TLS object otherwise |
| Exit `2` | Low header score or soon-expiring certificate                        |

## Develop

```bash
npm run format
npm run build
npm test
npm run test:integration   # optional live URL probes
npm run format:check
```

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for module layout and extension points.

## Ethics

Use only on systems and content you are **authorized** to test. See
[SECURITY.md](./SECURITY.md).

## License

Licensed under the [HackerX License](./LICENSE). Redistributions must retain copyright,
license text, and [NOTICE](./NOTICE) attribution per the license terms.
