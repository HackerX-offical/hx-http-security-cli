export interface RedirectHop {
  url: string;
  status: number;
  headers: Record<string, string>;
}

export interface FetchChainResult {
  hops: RedirectHop[];
  finalUrl: string;
  finalStatus: number;
  finalHeaders: Headers;
}

const DEFAULT_MAX_REDIRECTS = 10;

export async function fetchWithRedirectChain(
  startUrl: string,
  options: {
    maxRedirects?: number;
    timeoutMs?: number;
    fetchImpl?: typeof fetch;
  } = {},
): Promise<FetchChainResult> {
  const max = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  const fetchFn = options.fetchImpl ?? fetch;
  const hops: RedirectHop[] = [];
  let current = normalizeUrl(startUrl);

  for (let i = 0; i <= max; i++) {
    const res = await fetchFn(current, {
      redirect: 'manual',
      signal: AbortSignal.timeout(options.timeoutMs ?? 20000),
      headers: {
        'User-Agent': 'hx-http-security-cli/1.0 (+authorized assessment)',
      },
    });

    const headerObj: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headerObj[k.toLowerCase()] = v;
    });

    hops.push({ url: current, status: res.status, headers: headerObj });

    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get('location');
      if (!loc) break;
      current = new URL(loc, current).toString();
      continue;
    }

    return {
      hops,
      finalUrl: current,
      finalStatus: res.status,
      finalHeaders: res.headers,
    };
  }

  throw new Error(`Exceeded maximum redirects (${max})`);
}

export function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}
