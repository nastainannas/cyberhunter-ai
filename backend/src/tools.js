// Recon & assessment tools — authorized testing only.
import net from "node:net";
import dns from "node:dns/promises";

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
  1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
];

const SERVICES = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
  110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
  445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
  3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
  6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
  9200: "Elasticsearch", 27017: "MongoDB",
};

function probePort(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(timeoutMs);
    const done = (state) => { sock.destroy(); resolve({ port, state, service: SERVICES[port] ?? "unknown" }); };
    sock.once("connect", () => done("open"));
    sock.once("timeout", () => done("filtered"));
    sock.once("error", () => done("closed"));
    sock.connect(port, host);
  });
}

export async function portScan(host, { ports = COMMON_PORTS, concurrency = 20, log = () => {} } = {}) {
  const results = [];
  let idx = 0;
  async function worker() {
    while (idx < ports.length) {
      const port = ports[idx++];
      const r = await probePort(host, port);
      if (r.state === "open") {
        log(`Port ${port} (${r.service}) OPEN`);
        results.push(r);
      }
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  return { host, open: results.sort((a, b) => a.port - b.port), scanned: ports.length };
}

export async function dnsLookup(host) {
  const out = { host };
  const types = [
    ["A", dns.resolve4], ["AAAA", dns.resolve6], ["MX", dns.resolveMx],
    ["NS", dns.resolveNs], ["TXT", dns.resolveTxt], ["CNAME", dns.resolveCname],
  ];
  for (const [name, fn] of types) {
    try { out[name.toLowerCase()] = await fn(host); }
    catch { out[name.toLowerCase()] = null; }
  }
  return out;
}

export async function fetchRobots(origin, log = () => {}) {
  const out = { url: origin + "/robots.txt", found: false, disallow: [], allow: [], sitemap: [] };
  try {
    const res = await fetch(origin + "/robots.txt", { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return out;
    out.found = true;
    const text = await res.text();
    for (const line of text.split("\n")) {
      const l = line.trim();
      if (/^disallow:/i.test(l)) out.disallow.push(l.split(":")[1].trim());
      else if (/^allow:/i.test(l)) out.allow.push(l.split(":")[1].trim());
      else if (/^sitemap:/i.test(l)) out.sitemap.push(l.split(":").slice(1).join(":").trim());
    }
    log(`robots.txt: ${out.disallow.length} disallow, ${out.allow.length} allow, ${out.sitemap.length} sitemap entries`);
    return out;
  } catch {
    return out;
  }
}

export async function httpMethodsProbe(url) {
  const methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE"];
  const supported = [];
  for (const m of methods) {
    try {
      const res = await fetch(url, { method: m, redirect: "manual", signal: AbortSignal.timeout(6000) });
      if (![404, 405].includes(res.status)) supported.push({ method: m, status: res.status });
    } catch { /* skip */ }
  }
  return supported;
}
