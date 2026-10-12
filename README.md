# hx-http-security-cli

Terminal-first HTTP security auditing: redirect chains, response header grading, and TLS
certificate inspection.

## Install

```bash
npm install
npm run build
```

## Commands

```bash
hx-http audit https://target.example
hx-http chain http://target.example
hx-http tls target.example
```

Use `--json` for scripting. Exit code `2` on audit scores below 70 or certs expiring
within 14 days.

## Tests

```bash
npm test
npm run test:integration
```

HackerX License

## License

Licensed under the [HackerX License](./LICENSE). Redistributions must retain copyright,
license text, and [NOTICE](./NOTICE) attribution per the license terms.
