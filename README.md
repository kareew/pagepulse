# PagePulse

Instant website report card — beautiful real-time security, SSL, DNS, and tech analysis with a halftone generative art UI.

Powered by [sentinel-mcp](https://github.com/kareew/sentinel-mcp).

## What it does

Enter any URL and get a live security report card in seconds. PagePulse streams results in real time as each scan completes:

| Scan | What it checks |
|---|---|
| HTTP Security Headers | HSTS, CSP, X-Frame-Options, and 7+ more headers — graded A+ to F |
| SSL/TLS Certificate | Cert validity, expiry, trust chain, protocol version, cipher strength |
| DNS & Email Security | SPF, DMARC, DKIM, CAA records — flags email spoofing risk |
| Technology Fingerprint | Detects web servers, frameworks, CMS, CDN/WAF from headers + HTML |
| Port Scan | 30 high-risk ports checked, flags exposed databases/RDP/Telnet |

Results include an overall grade, critical findings, MITRE ATT&CK mapping, and per-category score breakdowns.

## Design

- Halftone dot animated canvas background (mouse-reactive)
- Blue `#1a3adb` on cream `#f5f0e8` color palette
- Space Grotesk + Space Mono typography
- Real-time progress indicators via Server-Sent Events
- Animated grade circle rendered with canvas dots

## Quick start

```bash
# 1. Build sentinel-mcp (the scanning engine)
cd sentinel-mcp
npm install
npm run build

# 2. Start PagePulse
cd ../pagepulse
npm install
npm start
```

Open `http://localhost:3000` and scan any site.

## Tech stack

- **Frontend:** Vanilla HTML/CSS/JS, Canvas API, SSE
- **Backend:** Express.js (v5), Node.js
- **Scanning engine:** [sentinel-mcp](https://github.com/kareew/sentinel-mcp) — zero external dependencies, uses Node built-in `tls`, `dns`, `net`, `https`

## Authorization

Only scan targets you are authorized to test. This tool is intended for defensive security assessments, penetration testing engagements, and educational use.

## License

MIT
