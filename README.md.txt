---
 ![A banner image showing a pig hunting for truffles](banner.jpg)


```text
  --.--          ,---.,---.|         
    |  ,---..   .|__. |__. |    ,---.
    |  |    |   ||    |    |    |---'
    `  `    `---'`    `    `---'`---'
    ,---.o
    |---'.,---.,---.  
    |    ||   ||   |
    `    ``---|`---|
          `---'`---'

```

**Version:** 1.0 - Ready for sniffing.

TrufflePigg is a monolithic, all-in-one reconnaissance, fuzzing, and OSINT tool built in Node.js for domain and server(where the domain is hosted) analysis. It's designed to act as a Swiss Army knife for bug bounty hunters and penetration testers. It doesn't just scan ports; it sniffs out high-fidelity secrets, hunts for shadow-trust dependency takeovers, bypasses WAFs using HTTP/2 and Client Hints, and crawls deep into the application structure.

**Disclaimer:** *Of course this tool is for educational purposes and authorized security testing only. Don't point the pig at infrastructure you don't own or don't have explicit permission to test. And I(the author) is not to be held accountable for any damage caused by this tool.*

---

## Features

* **HTTP/2 Multiplexing & SOCKS5 Support:** By utilizing the `node:http2` and `node:tls` libraries, it forces HTTP/2 connections, which many legacy WAFs struggle to parse deeply. It integrates `socks-proxy-agent` and natively supports Tor routing.
* **WAF Header Spoofing:** It dynamically injects headers (`X-Forwarded-For`, `True-Client-IP`, etc.) spoofing internal or local IP addresses (e.g., `127.0.0.1`, `10.0.0.1`) to bypass poorly configured IP-based rate limiting.
* **Packet Fragmentation (Stealth Write):** Rather than sending a standard protocol payload all at once, the `stealthWrite` function chunks byte payloads (e.g., SMB or DB probes) into tiny pieces (8 bytes) with micro-delays (50ms). This fragments the payload across multiple TCP packets, breaking basic IDS signature matching.
 ```javascript
async function stealthWrite(socket, buffer, chunkSize = 8, delay = 50) {
  socket.setNoDelay(true); 
  for (let i = 0; i < buffer.length; i += chunkSize) {
    const chunk = buffer.subarray(i, i + chunkSize);
    socket.write(chunk); // Send tiny fragments
    if (i + chunkSize < buffer.length) {
      await new Promise(r => setTimeout(r, delay)); // Micro-sleep between packets
    }
  }
}

```
* **Browser Fingerprint Randomization:** It rotates between Windows/Chrome, Linux/Edge, and Android/Chrome User-Agents, injecting complete `Sec-CH-UA` client hint headers to appear as legitimate browser traffic.
* **Protocol-Specific Probes:** It uses hardcoded byte arrays to trigger responses from specific databases (PostgreSQL, MongoDB, MSSQL) and SMB services.
* **Vulnerability Verification:** * Checks FTP (Port 21) for Anonymous login allowances.
* Checks Redis (Port 6379) for unauthenticated public access.
* Checks SMTP (Ports 25/587) for Open Mail Relay vulnerabilities.


* **Automated CVE Lookup:** Once a service banner and version are identified (e.g., `Apache 2.4.49`), it automatically queries the NIST NVD API to fetch known CVEs and CVSS scores for that exact version.
* **Honeypot Detection:** It implements an `analyzeForHoneypot` heuristic. If it detects an unusually high port density (>12 open ports), duplicate banner signatures across random ports, or known honeypot strings (like `cowrie` or `dionaea`), it flags the target as a potential trap.

* **Triple-Probe Baseline Fuzzing:** Before fuzzing a directory, it requests three randomized, non-existent paths (e.g., `probe_123xyz.html`). It calculates the average byte length and the structural similarity between these 404/Catch-All pages. When fuzzing real targets, it compares the response against this baseline. If the structural similarity matches the baseline, it discards the result as a false positive.
 ```javascript
async function getBaseline(host, port, basePath, protocol) {
  const probes = [];
  // Send 3 random requests to establish what a "Not Found" page looks like
  for (let i = 0; i < 3; i++) {
    const randomStr = Math.random().toString(36).substring(2, 15);
    const url = `${protocol}://${host}:${port}${basePath}probe_${randomStr}.html`;
    const body = await fetchText(url);
    probes.push({ body: body || "", length: body ? body.length : 0 });
  }

  // Calculate similarity between the false responses to establish a baseline threshold
  const stability = getSimilarity(probes[0].body, probes[1].body);
  return { avgLength, stability, sampleBody: probes[0].body };
}

```
* **Breadcrumb Crawling:** Instead of just guessing directories, it scrapes the HTML of valid pages for internal links, recursively fuzzing the context of those new paths up to a specified "hop" depth.
* **Sitemap & Robots.txt Extraction:** It pulls `robots.txt` rules (specifically logging `Disallow` paths as sensitive targets) and recursively parses nested `<sitemapindex>` XML files to extract unlinked, hidden application endpoints.

* **Passive Subdomain Gathering:** It queries external sources to find subdomains without sending a single packet to the target infrastructure.
* **Subdomain Takeover Detection:** It checks CNAME records of discovered subdomains against a hardcoded list of `TAKEOVER_FINGERPRINTS` (AWS S3, GitHub Pages, Heroku, Shopify). If a matching CNAME is found, it visits the page to look for specific "Not Found" signatures, confirming a highly critical takeover vulnerability.
* **SaaS Fingerprinting via DNS:** It parses DNS TXT records to identify third-party SaaS integrations (e.g., Google Workspace, Atlassian, Stripe, DocuSign) based on domain verification strings.

* **Client-Side Secret Scraping via Entropy:** It crawls all imported `.js` files and runs regex patterns for API keys (AWS, Google, Stripe). To prevent false positives, it runs a **Shannon Entropy** calculation on the matched strings. High-entropy strings are flagged as genuine secrets, while low-entropy strings (e.g., `placeholder_key_xxxx`) are discarded based on contextual keywords.
 ```javascript
function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const charCounts = {};
  for (let i = 0; i < str.length; i++) {
    charCounts[str[i]] = (charCounts[str[i]] || 0) + 1;
  }
  let entropy = 0;
  const len = str.length;
  for (const char in charCounts) {
    const p = charCounts[char] / len;
    entropy -= p * Math.log2(p); // Shannon entropy formula
  }
  return entropy;
}

```
* **Shadow-Trust Dependency Analysis:** This is a standout feature. It parses the DOM for all external dependencies (`<script src="...">`, stylesheets, iframes). It then performs DNS lookups on those external domains. If an external domain returns `NXDOMAIN` (dead host), it flags a **Critical Shadow-Trust Alert**, indicating the target is loading code from an expired domain that an attacker could register to achieve Stored XSS. It also checks for orphaned S3 buckets used as dependencies.
```javascript
// Inside analyzeShadowTrust()
const isDead = await checkHostAvailability(hostname);

if (isDead) {
  log(`          [!!!] CRITICAL SHADOW-TRUST ALERT: Abandoned Dependency Found!`);
  log(`                └─ Dead Host: ${hostname}`);
  const refs = rawReferences.filter(r => r.source.includes(hostname));
  refs.slice(0, 2).forEach(r => log(`                └─ Injected via: <${r.tag}> ${r.source}`));
}

```

## Anonymity

TrufflePigg is built with a "Privacy-First" mindset for the operator. It employs multiple layers of obfuscation to ensure that your IP won't get logged or traced(I can't assure 100%).

 * **Tor Network Integration:** By using the --tor flag, TrufflePigg routes all primary HTTP/2 traffic through a SOCKS5 proxy (defaulting to 127.0.0.1:9050).
 *(Note: Ensure Tor is installed and running on port 9050 if you intend to use the --tor flag).*
 * **Proxy Rotation:** When you can't use Tor, this is a less anonymous proxy rotation feature. It automatically pulls fresh, elite-level proxies from public providers. And if a proxy dies during a scan, the tool detects the connection failure, discards the dead IP, and rotates to the next available one in the pool without stopping the scan.

## Prerequisites & Installation

TrufflePigg relies on several Node.js modules to handle stealth requests, proxying, and DOM parsing.

**Clone the repository:**
```bash
git clone https://github.com/nulsie/trufflepigg.git
cd trufflepigg

```
**or**

**Through npm**
```bash
npm install -g @nulsie/trufflepigg

```

**For help, just command:**
```bash
--guide, guide, help or h
```

**To make it work, just command:**
```bash
trufflepig [configuration commands if you are using them]

```



---

## Usage

Running the tool without arguments will execute a default scan using the built-in toolsets and settings.

```bash
trufflepigg

```

*(When prompted, enter your target IP or domain).*

### Command Line Arguments

| Argument | Description |
| --- | --- |
| `--guide`, `-h` | Display the help guide (what else do you think it'll do?). |
| `--mode [web, infra, both]` | Set the scan mode. (Default: `web`). |
| `--ports [p1,p2,...]` | Specify custom ports to scan (e.g., `--ports 80,443,8080`). |
| `--breadcrumb` | Enable breadcrumb crawling to discover and analyze internal links. |
| `--hops [num]` | Set the maximum depth for breadcrumb crawling. (Default: `3`). |
| `--protate` | Enable automatic proxy rotation via ProxyScrape. |
| `--tor [url]` | Enable Tor routing. Defaults to `socks5h://127.0.0.1:9050` if no URL is provided. |
| `--fuzzlist [path]` | Load a custom wordlist for directory fuzzing. |
| `--concurrency [num]` | Set maximum concurrent tasks to avoid dropping connections. (Default: `10`). |
| `--depth [num]` | Set web directory fuzzing recursion depth. (Default: `2`). |
| `--sleep [min,max]` | Set a random delay range in ms between requests (e.g., `--sleep 100,500`). |
| `--signatures [path]` | Load a custom JSON file for technology detection signatures. |

### Examples

**1. The "I want everything" Scan:**

```bash
./TrufflePigg.js --mode both --breadcrumb --concurrency 20

```

**2. The Stealth Scan (Tor + High Sleep):**

```bash
./TrufflePigg.js --tor --sleep 500,1500 --depth 1

```

**3. Targeted Infrastructure Scan:**

```bash
./TrufflePigg.js --mode infra --ports 21,22,25,445,3306,6379

```

## Note:

* **It's a Monolith:** Currently, the entire script lives in a single 3,187 line file.

-----


**Author:** nulsie
**License:** GNU GPL v3