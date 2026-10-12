import { fetchWithRedirectChain } from '../src/fetch.js';
import { auditSecurityHeaders } from '../src/headers.js';
import { inspectTls } from '../src/tls.js';

describe('live HTTP/TLS', () => {
  it('follows example.com redirect chain', async () => {
    const chain = await fetchWithRedirectChain('http://example.com');
    expect(chain.finalStatus).toBe(200);
    expect(chain.hops.length).toBeGreaterThanOrEqual(1);
  });

  it('audits example.com headers', async () => {
    const chain = await fetchWithRedirectChain('https://example.com');
    const audit = auditSecurityHeaders(
      chain.finalUrl,
      chain.finalStatus,
      chain.finalHeaders,
    );
    expect(audit.findings.length).toBeGreaterThan(0);
  });

  it('inspects example.com TLS', async () => {
    const tls = await inspectTls('example.com');
    expect(tls.error).toBeUndefined();
    expect(tls.subject).toBeDefined();
    expect(tls.daysRemaining).toBeGreaterThan(0);
  });
});
