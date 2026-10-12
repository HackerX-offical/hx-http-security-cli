# hx-http-security-cli architecture

HTTP security header and TLS audit CLI for authorized web assessments.

## Layout

```
src/
  cli.ts              # Commander entry (audit, chain, tls)
  index.ts            # Public package exports
  fetch.ts            # Redirect chain fetch
  tls.ts              # Direct TLS socket inspection
  headers/
    types.ts          # HeaderFinding, HeaderAuditResult
    utils.ts          # getHeader, headersToRaw, parseMaxAge
    scoring.ts        # Severity weights and score computation
    audit.ts          # Orchestrates all rules into one audit
    index.ts          # Barrel exports
    rules/
      hsts.ts         # Strict-Transport-Security
      csp.ts          # Content-Security-Policy
      clickjack.ts    # X-Frame-Options / frame-ancestors
      nosniff.ts      # X-Content-Type-Options
      referrer.ts     # Referrer-Policy
      permissions.ts  # Permissions-Policy
      disclosure.ts   # Server / X-Powered-By info findings
      index.ts

tests/
  helpers/mock-headers.ts
  headers/*.test.ts   # Unit tests per rule module + scoring + audit
  http.integration.test.ts
```

## Header audit flow

1. `auditSecurityHeaders(url, status, headers)` collects raw header map.
2. Each `rules/*.ts` module returns zero or more `HeaderFinding` objects.
3. `scoring.ts` sums severity penalties and derives a 0–100 score.
4. CLI `audit` command fetches via `fetch.ts`, runs the audit, prints or emits JSON.

## Develop

```bash
npm install
npm run build
npm test
npm run test:integration   # optional network tests
```

See [SECURITY.md](./SECURITY.md) for authorized use.
