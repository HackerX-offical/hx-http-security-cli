import tls from 'node:tls';

export interface TlsInspectResult {
  host: string;
  port: number;
  authorized: boolean;
  protocol?: string;
  cipher?: string;
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  altNames?: string[];
  error?: string;
}

export function inspectTls(host: string, port = 443, timeoutMs = 10000): Promise<TlsInspectResult> {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const cipher = socket.getCipher();

      let daysRemaining: number | undefined;
      if (cert.valid_to) {
        const end = new Date(cert.valid_to);
        daysRemaining = Math.floor((end.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
      }

      const altNames: string[] = [];
      const alt = cert.subjectaltname;
      if (typeof alt === 'string') {
        alt.split(',').forEach((part) => {
          const m = /DNS:([^,\s]+)/.exec(part);
          if (m?.[1]) altNames.push(m[1]);
        });
      }

      const subjectCn = cert.subject?.CN;
      const issuerCn = cert.issuer?.CN;

      socket.end();
      resolve({
        host,
        port,
        authorized,
        protocol: cipher?.version,
        cipher: cipher?.name,
        subject: Array.isArray(subjectCn) ? subjectCn[0] : subjectCn,
        issuer: Array.isArray(issuerCn) ? issuerCn[0] : issuerCn,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysRemaining,
        altNames,
      });
    });

    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      resolve({ host, port, authorized: false, error: 'TLS timeout' });
    });

    socket.on('error', (err) => {
      resolve({
        host,
        port,
        authorized: false,
        error: err.message,
      });
    });
  });
}
