export function mockHeaders(map: Record<string, string>): Headers {
  const h = new Headers();
  for (const [k, v] of Object.entries(map)) {
    h.set(k, v);
  }
  return h;
}
