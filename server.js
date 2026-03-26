import express from "express";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { scanHttpSecurity } from "../sentinel-mcp/dist/tools/http-security.js";
import { checkSsl } from "../sentinel-mcp/dist/tools/ssl-check.js";
import { dnsRecon } from "../sentinel-mcp/dist/tools/dns-recon.js";
import { portScan } from "../sentinel-mcp/dist/tools/port-scan.js";
import { fingerprintTech } from "../sentinel-mcp/dist/tools/tech-fingerprint.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = 3000;

app.use(express.static(join(__dirname, "public")));
app.use(express.json());

// SSE endpoint for real-time scan progress
app.get("/api/scan", async (req, res) => {
  const target = req.query.url;
  if (!target) {
    return res.status(400).json({ error: "Missing url parameter" });
  }

  // Set up SSE
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const send = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  const results = {};

  // Run scans sequentially so the user sees real-time progress
  const scans = [
    {
      name: "http",
      label: "HTTP Security Headers",
      fn: () => scanHttpSecurity(target),
    },
    {
      name: "ssl",
      label: "SSL/TLS Certificate",
      fn: () => checkSsl(target),
    },
    {
      name: "dns",
      label: "DNS Records & Email Security",
      fn: () => dnsRecon(target),
    },
    {
      name: "tech",
      label: "Technology Fingerprinting",
      fn: () => fingerprintTech(target),
    },
    {
      name: "ports",
      label: "Port Scanning",
      fn: () => portScan(target, { timeout: 2000 }),
    },
  ];

  for (const scan of scans) {
    send("progress", { step: scan.name, label: scan.label, status: "running" });
    try {
      results[scan.name] = await scan.fn();
      send("progress", { step: scan.name, label: scan.label, status: "done" });
    } catch (err) {
      results[scan.name] = { error: err.message };
      send("progress", { step: scan.name, label: scan.label, status: "error", error: err.message });
    }
  }

  // Calculate overall score
  const scores = [];
  if (results.http?.score != null) scores.push(results.http.score);
  if (results.ssl?.score != null) scores.push(results.ssl.score);
  if (results.dns) {
    const dp = results.dns.securityChecks?.filter((c) => c.passed).length || 0;
    const dt = results.dns.securityChecks?.length || 1;
    scores.push(Math.round((dp / dt) * 100));
  }
  if (results.ports) {
    const crit = results.ports.openPorts?.filter((p) => p.risk === "critical").length || 0;
    const high = results.ports.openPorts?.filter((p) => p.risk === "high").length || 0;
    scores.push(Math.max(0, 100 - crit * 25 - high * 10));
  }

  const overall = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
  const grade = overall >= 90 ? "A+" : overall >= 80 ? "A" : overall >= 70 ? "B" : overall >= 60 ? "C" : overall >= 50 ? "D" : "F";

  // Build critical findings
  const criticalFindings = [];
  if (results.http?.checks) {
    results.http.checks
      .filter((c) => !c.present && c.severity === "critical")
      .forEach((c) => criticalFindings.push({ type: "header", detail: `Missing: ${c.header}`, severity: "critical" }));
  }
  if (results.ssl?.checks) {
    results.ssl.checks
      .filter((c) => !c.passed && c.severity === "critical")
      .forEach((c) => criticalFindings.push({ type: "ssl", detail: c.detail, severity: "critical" }));
  }
  if (results.dns?.mailSecurity) {
    if (!results.dns.mailSecurity.hasSPF) criticalFindings.push({ type: "dns", detail: "No SPF record — email spoofing risk", severity: "critical" });
    if (!results.dns.mailSecurity.hasDMARC) criticalFindings.push({ type: "dns", detail: "No DMARC record — email spoofing risk", severity: "critical" });
  }
  if (results.ports?.openPorts) {
    results.ports.openPorts
      .filter((p) => p.risk === "critical")
      .forEach((p) => criticalFindings.push({ type: "port", detail: `Port ${p.port}/${p.service} exposed`, severity: "critical" }));
  }

  // MITRE mapping
  const mitre = [];
  if (results.http?.checks?.some((c) => c.header === "content-security-policy" && !c.present)) {
    mitre.push({ id: "T1189", name: "Drive-by Compromise" });
  }
  if (results.dns?.mailSecurity && (!results.dns.mailSecurity.hasSPF || !results.dns.mailSecurity.hasDMARC)) {
    mitre.push({ id: "T1566", name: "Phishing" });
  }
  if (results.ports?.openPorts?.some((p) => [22, 3389, 23].includes(p.port))) {
    mitre.push({ id: "T1133", name: "External Remote Services" });
  }
  if (results.tech?.serverInfo?.server || results.tech?.serverInfo?.poweredBy) {
    mitre.push({ id: "T1592", name: "Gather Victim Host Info" });
  }

  send("complete", {
    target,
    overall,
    grade,
    http: results.http,
    ssl: results.ssl,
    dns: results.dns,
    tech: results.tech,
    ports: results.ports,
    criticalFindings,
    mitre,
    timestamp: new Date().toISOString(),
  });

  res.end();
});

app.listen(PORT, () => {
  console.log(`PagePulse running at http://localhost:${PORT}`);
});
