export function getHeader(headers: Headers, name: string): string | undefined {
  return headers.get(name) ?? headers.get(name.toLowerCase()) ?? undefined;
}

export function headersToRaw(headers: Headers): Record<string, string> {
  const raw: Record<string, string> = {};
  headers.forEach((value, key) => {
    raw[key.toLowerCase()] = value;
  });
  return raw;
}

export function parseMaxAge(hsts: string): number | null {
  const match = /max-age=(\d+)/i.exec(hsts);
  return match ? Number(match[1]) : null;
}
