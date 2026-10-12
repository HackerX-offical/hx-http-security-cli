#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { auditSecurityHeaders } from './headers.js';
import { fetchWithRedirectChain, normalizeUrl } from './fetch.js';
import { inspectTls } from './tls.js';

const program = new Command();

program
  .name('hx-http')
  .description('HTTP/TLS security checks for authorized web assessments')
  .version('1.0.0');

function severityColor(s: string): (t: string) => string {
  switch (s) {
    case 'critical':
    case 'high':
      return chalk.red;
    case 'medium':
      return chalk.yellow;
    case 'low':
      return chalk.cyan;
    default:
      return chalk.dim;
  }
}

program
  .command('audit')
  .description('Audit security headers for a URL')
  .argument('<url>', 'https URL or hostname')
  .option('--json', 'JSON output')
  .action(async (url: string, opts: { json?: boolean }) => {
    try {
      const chain = await fetchWithRedirectChain(normalizeUrl(url));
      const audit = auditSecurityHeaders(chain.finalUrl, chain.finalStatus, chain.finalHeaders);

      if (opts.json) {
        console.log(JSON.stringify({ chain, audit }, null, 2));
        return;
      }

      console.log(chalk.bold(`URL: ${chain.finalUrl}`));
      console.log(`Status: ${chain.finalStatus}`);
      console.log(`Score: ${audit.score}/100\n`);

      for (const f of audit.findings) {
        const color = severityColor(f.severity);
        console.log(`${color(`[${f.severity}]`)} ${f.header}: ${f.message}`);
      }

      process.exit(audit.score < 70 ? 2 : 0);
    } catch (err) {
      console.error(chalk.red(err instanceof Error ? err.message : String(err)));
      process.exit(1);
    }
  });

program
  .command('chain')
  .description('Show redirect chain')
  .argument('<url>', 'starting URL')
  .option('--json', 'JSON output')
  .action(async (url: string, opts: { json?: boolean }) => {
    try {
      const chain = await fetchWithRedirectChain(normalizeUrl(url));
      if (opts.json) {
        console.log(JSON.stringify(chain, null, 2));
        return;
      }
      chain.hops.forEach((h, i) => {
        console.log(`${i + 1}. ${h.status} ${h.url}`);
      });
      console.log(chalk.dim(`\nFinal: ${chain.finalUrl}`));
    } catch (err) {
      console.error(chalk.red(err instanceof Error ? err.message : String(err)));
      process.exit(1);
    }
  });

program
  .command('tls')
  .description('Inspect TLS certificate (direct socket)')
  .argument('<host>', 'hostname')
  .option('-p, --port <port>', 'port', '443')
  .option('--json', 'JSON output')
  .action(async (host: string, opts: { port: string; json?: boolean }) => {
    const port = Number(opts.port);
    const result = await inspectTls(host, port);
    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      if (result.error) {
        console.error(chalk.red(result.error));
        process.exit(1);
      }
      console.log(chalk.bold(`${result.host}:${result.port}`));
      console.log(`Authorized: ${result.authorized ? 'yes' : 'no'}`);
      console.log(`Subject: ${result.subject ?? 'n/a'}`);
      console.log(`Issuer: ${result.issuer ?? 'n/a'}`);
      console.log(`Valid: ${result.validFrom} → ${result.validTo}`);
      console.log(`Days remaining: ${result.daysRemaining ?? 'n/a'}`);
      if (result.altNames?.length) {
        console.log(`SANs: ${result.altNames.join(', ')}`);
      }
    }
    if (result.daysRemaining !== undefined && result.daysRemaining < 14) {
      process.exit(2);
    }
  });

program.parse();
