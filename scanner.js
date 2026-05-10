const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const tls = require('node:tls');
const net = require('node:net');
const dns = require('node:dns').promises;
const cheerio = require('cheerio');
const pLimit = require('p-limit');

const { 
  log, sleep, tstacksleep, fetchText, fetchBuffer, getJson, 
  getSimilarity, calculateShannonEntropy, promptYesNo, 
  getHumanHeaders, getWafEvasionHeaders 
} = require('./utils');

const { 
  COMMON_SITEMAPS, TECH_SIGNATURES_PRO, SECRET_PATTERNS, WAF_SIGNATURES, 
  INFRA_PORTS, COMMON_UDP_PORTS, DB_PROBES, TLD_PERMUTATIONS, 
  WHITELIST_DOMAINS, FUZZ_TARGETS, BROWSER_PROFILES
} = require('./data');

const { grabBanner, probeDatabase, probeSMB, probeUdpPort, getTlsIntel } = require('./sniffer');


let SCANNER_CONFIG = {
  concurrency: 10,
  fuzzDepth: 2,
  torAgent: undefined,
  rl: null
};

function updateScannerConfig(config) {
  SCANNER_CONFIG = { ...SCANNER_CONFIG, ...config };
}

async function lookupCVEs(software, version) {
  if (!software || software === 'Unknown' || software === 'Web Server' || !version || version === 'Unknown') {
    return null;
  }

  const query = encodeURIComponent(`${software} ${version}`);
  const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${query}&resultsPerPage=3`;

  try {
    const data = await getJson(apiUrl, SCANNER_CONFIG.torAgent);
    
    if (!data || !data.vulnerabilities || data.vulnerabilities.length === 0) {
      return [];
    }

    return data.vulnerabilities.map(v => {
      const cve = v.cve;
      let score = 'N/A';
      let severity = 'UNKNOWN';
      
      if (cve.metrics?.cvssMetricV31) {
        score = cve.metrics.cvssMetricV31[0].cvssData.baseScore;
        severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity;
      } else if (cve.metrics?.cvssMetricV2) {
        score = cve.metrics.cvssMetricV2[0].cvssData.baseScore;
        severity = cve.metrics.cvssMetricV2[0].baseSeverity;
      }

      return {
        id: cve.id,
        score: score,
        severity: severity,
        description: cve.descriptions[0]?.value.substring(0, 80) + '...'
      };
    }).sort((a, b) => (b.score !== 'N/A' ? b.score : 0) - (a.score !== 'N/A' ? a.score : 0)); 

  } catch (err) {
    return { error: 'API Rate Limited or Unavailable' };
  }
}

function identifyWAF(headers) {
  const detected = [];
  const headerKeys = Object.keys(headers).map(k => k.toLowerCase());

  for (const [name, sig] of Object.entries(WAF_SIGNATURES)) {
    const hasHeader = sig.headers.some(h => headerKeys.includes(h));
    const hasValueMatch = Object.values(headers).some(val => 
      typeof val === 'string' && sig.regex.test(val)
    );

    if (hasHeader || hasValueMatch) {
      detected.push(name);
    }
  }
  return detected.length > 0 ? detected : null;
}

function analyzeForHoneypot(openPorts) {
  const findings = [];
  
  if (openPorts.length > 12) {
    findings.push(`High Port Density (${openPorts.length} ports open) - Possible Port-Spoofing Honeypot`);
  }

  const banners = openPorts
    .filter(p => p.banner && p.banner.software !== 'Unknown')
    .map(p => p.banner.software);
    
  const bannerCounts = banners.reduce((acc, b) => {
    acc[b] = (acc[b] || 0) + 1;
    return acc;
  }, {});

  for (const [banner, count] of Object.entries(bannerCounts)) {
    if (count > 3) {
      findings.push(`Duplicate Banner Pattern: "${banner}" found on ${count} different ports.`);
    }
  }

  const honeypotBanners = [/cowrie/i, /honeypot/i, /dionaea/i];
  openPorts.forEach(p => {
    if (p.banner && honeypotBanners.some(re => re.test(JSON.stringify(p.banner)))) {
      findings.push(`Direct Signature Match on Port ${p.port}: Known Honeypot software detected.`);
    }
  });

  return findings;
}

function checkAnonymousFtp(host) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(4000);
    let step = 0;
    let isVulnerable = false;

    socket.on('data', (data) => {
      const response = data.toString();
      if (step === 0 && response.includes('220')) {
        socket.write('USER anonymous\r\n');
        step++;
      } else if (step === 1 && (response.includes('331') || response.includes('230'))) {
        socket.write('PASS anonymous@dipmat.local\r\n');
        step++;
      } else if (step === 2) {
        if (response.includes('230')) isVulnerable = true; 
        socket.destroy();
      }
    });

    socket.on('error', () => { socket.destroy(); resolve(false); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('close', () => resolve(isVulnerable));
    socket.connect(21, host);
  });
}

function checkRedisAuth(host) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(3000);
    let isVulnerable = false;

    socket.on('connect', () => {
      socket.write('INFO\r\n'); 
    });

    socket.on('data', (data) => {
      const response = data.toString();
      if (response.includes('redis_version') && !response.includes('-NOAUTH')) {
        isVulnerable = true;
      }
      socket.destroy();
    });

    socket.on('error', () => { socket.destroy(); resolve(false); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('close', () => resolve(isVulnerable));
    socket.connect(6379, host);
  });
}

function checkOpenRelay(host, port) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(5000);
    let step = 0;
    let isVulnerable = false;

    socket.on('data', (data) => {
      const response = data.toString();
      if (step === 0 && response.includes('220')) {
        socket.write('HELO dipmat.local\r\n');
        step++;
      } else if (step === 1 && response.includes('250')) {
        socket.write('MAIL FROM:<test@dipmat.local>\r\n');
        step++;
      } else if (step === 2 && response.includes('250')) {
        socket.write('RCPT TO:<external-test-relay@gmail.com>\r\n');
        step++;
      } else if (step === 3) {
        if (response.includes('250') || response.includes('Relaying allowed')) {
          isVulnerable = true;
        }
        socket.destroy();
      }
    });

    socket.on('error', () => { socket.destroy(); resolve(false); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('close', () => resolve(isVulnerable));
    socket.connect(port, host);
  });
}

async function scanInfrastructure(targetIp) {
  log(`\n--- [ INFRASTRUCTURE DEEP SCAN ] ---`);
  log(`[*] Targeting Database, Mail, and Admin Services...`);
  
  const tcpPromises = INFRA_PORTS.map(port => {
    if (port === 445) return probeSMB(targetIp); 
    if (DB_PROBES[port]) return probeDatabase(port, targetIp);
    return grabBanner(port, targetIp);
  });
  
  const udpPromises = COMMON_UDP_PORTS.map(port => probeUdpPort(port, targetIp));
  
  const [tcpResults, udpResults] = await Promise.all([
    Promise.all(tcpPromises),
    Promise.all(udpPromises)
  ]);

  const openTcp = tcpResults.filter(r => r !== null && r.open);
  const openUdp = udpResults.filter(r => r !== null && r.open);

  if (openTcp.length === 0 && openUdp.length === 0) {
    log(`  [-] No standard infrastructure ports detected open.`);
    return;
  }

  if (openUdp.length > 0) {
    log(`\n  [#] Discovered ${openUdp.length} Open UDP Ports:`);
    openUdp.forEach(r => {
      log(`      [+] Port ${r.port}/UDP - Response: ${r.banner || 'No payload data returned'}`);
    });
  }

  for (const r of openTcp.sort((a, b) => a.port - b.port)) {
    log(`\n  [+] Port ${r.port} OPEN`);
    
    if (r.banner) {
      log(`      └─ Service: ${r.banner.software} (v: ${r.banner.version})`);
      if (r.banner.version !== 'Unknown') {
        const cves = await lookupCVEs(r.banner.software, r.banner.version);
        if (cves && cves.length > 0) {
          log(`      [!] Found ${cves.length} potential CVEs:`);
          cves.slice(0, 3).forEach(cve => {
            log(`          - ${cve.id} (CVSS: ${cve.score})`);
          });
        }
      }
    }

    if (r.port === 21) {
      log(`      [*] Testing for Anonymous FTP Login...`);
      const isAnon = await checkAnonymousFtp(targetIp);
      if (isAnon) log(`      [!!!] CRITICAL: Anonymous FTP Login is ALLOWED.`);
      else log(`      [-] Anonymous FTP denied.`);
    }

    if (r.port === 6379) {
      log(`      [*] Testing Redis Authentication...`);
      const isOpen = await checkRedisAuth(targetIp);
      if (isOpen) log(`      [!!!] CRITICAL: Redis is open to the public without a password.`);
      else log(`      [-] Redis requires authentication.`);
    }

    if ([25, 587].includes(r.port)) {
      log(`      [*] Testing for SMTP Open Relay...`);
      const isRelay = await checkOpenRelay(targetIp, r.port);
      if (isRelay) log(`      [!!!] CRITICAL: Server is acting as an Open Mail Relay.`);
      else log(`      [-] Server safely rejects external relaying.`);
    }
  }
}

function checkSecurityHeaders(host, port) {
  return new Promise((resolve) => {
    const isHttps = port === 443 || port === 8443;
    const protocol = isHttps ? https : http;
    const c_url = `${protocol === https ? 'https' : 'http'}://${host}:${port}/`;
    const url = isHttps ? `https://${host}` : `http://${host}:${port}`;
    
    const options = {
      method: 'HEAD', timeout: 5000, rejectUnauthorized: false, agent: SCANNER_CONFIG.torAgent,
      headers: { 'User-Agent': getHumanHeaders(c_url)["user-agent"], ...getWafEvasionHeaders() }  
    };

    const req = protocol.request(url, options, (res) => {
      const headers = res.headers;
      const wafs = identifyWAF(headers);
      if (wafs) log(`      [!] WAF DETECTED: ${wafs.join(', ')}`);
      
      const securityHeaders = {
        'Strict-Transport-Security': headers['strict-transport-security'],
        'Content-Security-Policy': headers['content-security-policy'],
        'X-Frame-Options': headers['x-frame-options'],
        'X-Content-Type-Options': headers['x-content-type-options']
      };
      resolve({ success: true, data: securityHeaders });
    });

    req.on('timeout', () => { req.destroy(); resolve({ success: false, error: 'Timeout' }); });
    req.on('error', (err) => resolve({ success: false, error: err.message }));
    req.end();
  });
}

async function detectTechStack(host, port) {
  const isHttps = port === 443 || port === 8443;
  const protocol = isHttps ? https : http;
  
  return new Promise((resolve) => {
    const c_url = `${protocol === https ? 'https' : 'http'}://${host}:${port}/`;
    const options = {
      method: 'GET', timeout: 5000, rejectUnauthorized: false, agent: SCANNER_CONFIG.torAgent,
      headers: { 'User-Agent': getHumanHeaders(c_url)["user-agent"], ...getWafEvasionHeaders() }
    };

    const req = protocol.request(options, async (res) => {
      const headers = res.headers;
      const cookies = headers['set-cookie'] || [];
      let body = '';
      
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', async () => {
        const detected = [];
        const html = body.toLowerCase();

        for (const [name, sig] of Object.entries(TECH_SIGNATURES_PRO)) {
          let score = 0;
          if (sig.dom && sig.dom.some(regex => regex.test(html))) score++;

          const headerMatch = sig.headers && Object.entries(sig.headers).some(([key, regex]) => 
            headers[key] && regex.test(headers[key])
          );
          
          if (headerMatch || (sig.cookies && sig.cookies.some(re => cookies.some(c => re.test(c))))) score++;

          if (sig.files) {
            let fileFound = false;
            for (const path of sig.files) {
              await tstacksleep(300, 900); 
              const exists = await checkPathExists(protocol, host, port, path);
              if (exists) { fileFound = true; break; }
            }
            if (fileFound) score++;
          }
          if (score >= 2) detected.push(name);
        }
        resolve({ success: true, stack: detected });
      });
    });

    req.on('error', (err) => resolve({ success: false, error: err.message }));
    req.end();
  });
}

async function checkPathExists(protocol, host, port, path) {
  return new Promise((resolve) => {
    const c_url = `${protocol === https ? 'https' : 'http'}://${host}:${port}${path}`;
    const url = `${protocol === https ? 'https' : 'http'}://${host}:${port}${path}`;
    const options = { 
      method: 'HEAD', timeout: 2000, agent: SCANNER_CONFIG.torAgent, rejectUnauthorized: false,
      headers: { 'User-Agent': getHumanHeaders(c_url)["user-agent"], ...getWafEvasionHeaders() } 
    };
    
    const req = protocol.request(url, options, (res) => {
      res.resume();
      resolve(res.statusCode === 200 || res.statusCode === 403); 
    });
    req.on('error', () => resolve(false));
    req.end();
  });
}

async function getBaseline(host, port, basePath, protocol) {
  const probes = [];
  log(`          [*] Establishing Triple-Probe Baseline for ${basePath}...`);

  for (let i = 0; i < 3; i++) {
    const randomStr = Math.random().toString(36).substring(2, 15);
    const randomPath = (basePath.endsWith('/') ? basePath : basePath + '/') + `probe_${randomStr}.html`;
    const url = `${protocol === https ? 'https' : 'http'}://${host}:${port}${randomPath}`;
    
    const body = await fetchText(url, SCANNER_CONFIG.torAgent);
    probes.push({ body: body || "", length: body ? body.length : 0 });
    await sleep(100, 300); 
  }

  const [len1, len2, len3] = probes.map(p => p.length);
  const isDynamic = (len1 !== len2) || (len2 !== len3);
  const avgLength = Math.floor((len1 + len2 + len3) / 3);
  const stability = getSimilarity(probes[0].body, probes[1].body);

  log(`          [+] Baseline established. Avg Length: ${avgLength} | Stability: ${stability.toFixed(2)}%`);
  if (isDynamic) log(`          [!] Warning: Dynamic content detected in 404 responses.`);

  return { isDynamic, avgLength, stability, sampleBody: probes[0].body };
}

async function downloadExposedFiles(files, host, port) {
  const safeHost = host.replace(/[^a-zA-Z0-9.-]/g, '_');
  const dir = `loot_${safeHost}_${port}`;
  
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  log(`\n          [*] Downloading ${files.length} files to ./${dir}/ ...`);
  
  for (const file of files) {
    try {
      const fileContent = await fetchBuffer(file.url, SCANNER_CONFIG.torAgent);
      if (fileContent) {
        const rawName = file.path.split('/').filter(Boolean).join('_') || 'unknown_file';
        const safeFileName = rawName.replace(/[^a-zA-Z0-9.-]/g, '_');
        const savePath = `${dir}/${safeFileName}`;
        
        fs.writeFileSync(savePath, fileContent);
        log(`              [+] Saved: ${savePath}`);
      } else {
        log(`              [-] Failed to download (or not 200 OK): ${file.url}`);
      }
    } catch (err) {
      log(`              [-] Error downloading ${file.url}: ${err.message}`);
    }
  }
  log(`          [*] Download phase complete.\n`);
}

async function fuzzWeb(host, port, basePath = '/', currentDepth = 0, maxDepth = 2, visited = new Set(), exposedFiles = []) {
  if (currentDepth > maxDepth) return;
  const isHttps = port === 443 || port === 8443;
  const protocol = isHttps ? https : http;
  let foundCount = 0;

  if (!basePath.startsWith('/')) basePath = '/' + basePath;
  if (!basePath.endsWith('/')) basePath += '/';

  if (currentDepth === 0) log(`\n      [*] Fuzzing Port ${port} with concurrency limit...`);

  const baseline = await getBaseline(host, port, basePath, protocol);
  const isCatchAll = baseline && (baseline.status === 200 || baseline.status === 301 || baseline.status === 302);
  
  if (isCatchAll && currentDepth === 0) log(`          [!] Wildcard/Catch-All routing detected. Applying advanced heuristics...`);

  const directoriesToRecurse = [];
  const limit = pLimit(SCANNER_CONFIG.concurrency);

  const tasks = FUZZ_TARGETS.map((target) => {
    return limit(async () => {
      await sleep(200, 800);
      const cleanTarget = target.startsWith('/') ? target.slice(1) : target;
      const fullPath = (basePath.endsWith('/') ? basePath : basePath + '/') + cleanTarget;

      if (visited.has(fullPath)) return;
      visited.add(fullPath);

      const performProbe = (method) => {
        return new Promise((resolve) => {
          const c_url = `${protocol === https ? 'https' : 'http'}://${host}:${port}${fullPath}`;
          const options = {
            method: method, hostname: host, port: port, path: fullPath, timeout: 2000,
            agent: SCANNER_CONFIG.torAgent, rejectUnauthorized: false,
            headers: { 'User-Agent': getHumanHeaders(c_url)["user-agent"], ...getWafEvasionHeaders() }
          };

          const req = protocol.request(options, (res) => {
            res.resume(); 
            resolve({ status: res.statusCode, location: res.headers.location, headers: res.headers });
          });

          req.on('error', () => resolve({ status: 0, headers: {} }));
          req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {} }); });
          req.end();
        });
      };

      let responseData = await performProbe('HEAD');
      if (responseData.status === 405) responseData = await performProbe('GET');

      const { status, location, headers } = responseData;
      let isLegit = false;

      if (status === 200) {
        const targetUrl = (isHttps ? 'https://' : 'http://') + host + ':' + port + fullPath;
        const currentBody = await fetchText(targetUrl, SCANNER_CONFIG.torAgent);
        const similarityTo404 = getSimilarity(baseline.sampleBody, currentBody);
        isLegit = similarityTo404 < baseline.stability;
      }

      if (isLegit) {
        log(`          [!] EXPOSED:   ${fullPath.padEnd(25)} (200 OK)`);
        foundCount++;
        if (!cleanTarget.endsWith('/')) exposedFiles.push({ url: (isHttps ? 'https://' : 'http://') + host + ':' + port + fullPath, path: fullPath });
        if (cleanTarget.endsWith('/') || target.includes('.')) {
          if (cleanTarget.endsWith('/')) directoriesToRecurse.push(fullPath);
        }
      } else if (status === 403) {
        log(`          [+] PROTECTED: ${fullPath.padEnd(25)} (403 Forbidden)`);
        foundCount++;
        if (cleanTarget.endsWith('/')) directoriesToRecurse.push(fullPath);
      } else if (status === 301 || status === 302) {
        if (!isCatchAll || location !== baseline.location) {
          if (location && (location.endsWith(fullPath + '/') || location.includes(fullPath + '/'))) {
            const dirPath = fullPath.endsWith('/') ? fullPath : fullPath + '/';
            log(`          [+] DIRECTORY: ${dirPath.padEnd(25)} (${status} Redirect)`);
            directoriesToRecurse.push(dirPath);
          }
        }
      }
    });
  });

  await Promise.all(tasks);

  for (const dir of directoriesToRecurse) {
    log(`\n          [*] Recursing into directory: ${dir}`);
    await fuzzWeb(host, port, dir, currentDepth + 1, maxDepth, visited, exposedFiles);
  }

  if (currentDepth === 0 && exposedFiles.length > 0) {
    if (SCANNER_CONFIG.rl) {
      const downloadChoice = await promptYesNo(SCANNER_CONFIG.rl, `\n          [?] Found ${exposedFiles.length} exposed files. Do you want to download them? (y/n): `);
      if (downloadChoice === 'y' || downloadChoice === 'yes') {
        await downloadExposedFiles(exposedFiles, host, port);
      } else {
        log(`          [*] Skipped downloading files.\n`);
      }
    } else {
      log(`          [!] Found ${exposedFiles.length} exposed files. (Interactive mode disabled)\n`);
    }
  }
}


async function advancedDiscoveryScan(host, port) {
  const isHttps = port === 443 || port === 8443;
  const baseUrl = isHttps ? `https://${host}` : `http://${host}:${port}`;
  
  log(`\n      [*] Executing Advanced Discovery (Robots/Sitemaps) on Port ${port}...`);

  let discoveredSitemaps = [];
  const sensitivePaths = new Set();
  const robotsBody = await fetchText(`${baseUrl}/robots.txt`, SCANNER_CONFIG.torAgent);
  
  if (robotsBody && robotsBody.length > 5) {
    log(`          [+] robots.txt FOUND! (${robotsBody.length} bytes)`);
    const lines = robotsBody.split(/\r?\n/);
    
    for (let line of lines) {
      line = line.trim();
      if (line.toLowerCase().startsWith('disallow:')) {
        const path = line.split(':')[1]?.trim();
        if (path && path !== '/') sensitivePaths.add(path);
      }
      if (line.toLowerCase().startsWith('sitemap:')) {
        const url = line.split(/sitemap:/i)[1]?.trim();
        if (url) discoveredSitemaps.push(url);
      }
    }
    if (SCANNER_CONFIG.rl) {
      const saveChoice = await promptYesNo(SCANNER_CONFIG.rl, `\n          [?] Do you want to save this robots.txt to a file? (y/n): `);
      if (saveChoice === 'y' || saveChoice === 'yes') {
        const safeHost = host.replace(/[^a-zA-Z0-9.-]/g, '_');
        const filename = `${safeHost}_${port}_robots.txt`;
        try {
          fs.writeFileSync(filename, robotsBody);
          log(`          [+] SUCCESS: Saved raw contents to ./${filename}\n`);
        } catch (err) {
          log(`          [-] ERROR: Failed to save file (${err.message})\n`);
        }
      } else {
        log(`          [*] Skipped saving file.\n`);
      }
    }
  }

  if (discoveredSitemaps.length === 0) {
    for (const path of COMMON_SITEMAPS) {
      const exists = await checkPathExists(isHttps ? https : http, host, port, path);
      if (exists) {
        discoveredSitemaps.push(`${baseUrl}${path}`);
        break; 
      }
    }
  }

  if (discoveredSitemaps.length > 0) {
    log(`          [*] Parsing Sitemaps...`);
    const allExtractedUrls = new Set();
    
    for (const sm of discoveredSitemaps) {
      await crawlSitemap(sm, new Set(), allExtractedUrls);
    }

    if (allExtractedUrls.size > 0) {
      log(`          [!] SUCCESS: Extracted ${allExtractedUrls.size} unique URLs from sitemaps.`);
      
      // RESTORED: Juicy URL Analysis
      const interestingKeywords = ['admin', 'login', 'api', 'dashboard', 'user', 'config', 'dev'];
      const juicyUrls = Array.from(allExtractedUrls).filter(url => 
        interestingKeywords.some(keyword => url.toLowerCase().includes(keyword))
      );

      if (juicyUrls.length > 0) {
        log(`              -> Found ${juicyUrls.length} potentially sensitive URLs in sitemap:`);
        juicyUrls.slice(0, 3).forEach(url => log(`                 └─ ${url}`));
        if (juicyUrls.length > 3) log(`                 └─ ...and more`);
      }
    }
  }
  return Array.from(sensitivePaths);
}

async function crawlSitemap(sitemapUrl, visitedSitemaps = new Set(), extractedUrls = new Set()) {
  if (visitedSitemaps.has(sitemapUrl) || visitedSitemaps.size > 15) return extractedUrls;
  visitedSitemaps.add(sitemapUrl);

  const body = await fetchText(sitemapUrl, SCANNER_CONFIG.torAgent);
  if (!body) return extractedUrls;

  if (body.includes('<sitemapindex')) {
    const subSitemaps = [...body.matchAll(/<loc>(.*?)<\/loc>/g)].map(m => m[1]);
    for (const sub of subSitemaps.slice(0, 5)) await crawlSitemap(sub, visitedSitemaps, extractedUrls);
  } else if (body.includes('<urlset')) {
    const urls = [...body.matchAll(/<loc>(.*?)<\/loc>/g)].map(m => m[1]);
    urls.forEach(u => extractedUrls.add(u));
  }
  return extractedUrls;
}

function isHighFidelitySecret(match, fullText, minEntropy = 3.8) {
  const entropy = calculateShannonEntropy(match);
  if (!match.includes('.') && !match.includes('/')) {
      if (entropy < minEntropy) return false; 
  }

  const matchIndex = fullText.indexOf(match);
  if (matchIndex > -1) {
    const start = Math.max(0, matchIndex - 40);
    const context = fullText.substring(start, matchIndex).toLowerCase();
    const falsePositiveKeywords = ['example', 'test', 'sample', 'placeholder', 'dummy', 'your_', 'xxxx'];
    if (falsePositiveKeywords.some(keyword => context.includes(keyword))) return false;
  }
  return true;
}

async function scrapeJsForSecrets(host, port) {
  const isHttps = port === 443 || port === 8443;
  const baseUrl = isHttps ? `https://${host}` : `http://${host}:${port}`;
  
  log(`\n      [*] Crawling client-side JS for secrets on Port ${port}...`);
  const htmlBody = await fetchText(baseUrl, SCANNER_CONFIG.torAgent);
  if (!htmlBody) return;

  const $ = cheerio.load(htmlBody);
  const jsUrls = new Set();

  $('script[src]').each((i, el) => {
    let jsPath = $(el).attr('src');
    if (!jsPath) return;
    
    if (jsPath.startsWith('http')) {
      jsUrls.add(jsPath);
    } else if (jsPath.startsWith('//')) {
      jsUrls.add((isHttps ? 'https:' : 'http:') + jsPath);
    } else {
      try { jsUrls.add(new URL(jsPath, baseUrl).href); } catch (e) {}
    }
  });

  let secretsFound = 0;
  for (const jsUrl of jsUrls) {
    const jsBody = await fetchText(jsUrl, SCANNER_CONFIG.torAgent);
    if (!jsBody) continue;

    let fileReported = false;
    for (const [name, regex] of Object.entries(SECRET_PATTERNS)) {
      const finds = [...jsBody.matchAll(regex)];
      if (finds.length > 0) {
        if (!fileReported) {
          log(`          [!] Secrets discovered in: ${jsUrl}`);
          fileReported = true;
        }
        
        const uniqueFinds = [...new Set(finds.map(f => f[0]))];
        for (const f of uniqueFinds) {
           if (isHighFidelitySecret(f, jsBody)) {
               const entropyScore = calculateShannonEntropy(f).toFixed(2);
               log(`              -> [${name}]: ${f} (Entropy: ${entropyScore})`);
               secretsFound++;
           }
        }
      }
    }
  }
  if (secretsFound > 0) log(`          [*] Scan complete: ${secretsFound} sensitive items identified.`);
}

async function checkHostAvailability(hostname) {
  try {
    await dns.resolve4(hostname);
    return false; 
  } catch (err) {
    if (err.code === 'ENOTFOUND') return true; 
    return false;
  }
}

async function checkS3Claimable(hostname) {
  return new Promise((resolve) => {
    const req = https.get(`https://${hostname}`, { timeout: 5000, agent: SCANNER_CONFIG.torAgent }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve(body.includes('NoSuchBucket')));
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
  });
}

async function analyzeShadowTrust(host, port) {
  const isHttps = port === 443 || port === 8443;
  const baseUrl = isHttps ? `https://${host}` : `http://${host}:${port}`;
  
  log(`\n      [*] Executing Shadow-Trust Dependency Analysis on Port ${port}...`);
  const htmlBody = await fetchText(baseUrl, SCANNER_CONFIG.torAgent);
  if (!htmlBody) return;

  const $ = cheerio.load(htmlBody);
  const externalDomains = new Set();
  const rawReferences = [];

  $('script[src], link[href], img[src], iframe[src], form[action], a[href]').each((i, el) => {
    const urlAttr = $(el).attr('src') || $(el).attr('href') || $(el).attr('action');
    if (!urlAttr || !urlAttr.startsWith('http') && !urlAttr.startsWith('//')) return;

    try {
      const fullUrl = urlAttr.startsWith('//') ? `https:${urlAttr}` : urlAttr;
      const urlObj = new URL(fullUrl);
      const hostname = urlObj.hostname.toLowerCase();
      
      if (!hostname.includes(host) && !WHITELIST_DOMAINS.some(wd => hostname.endsWith(wd))) {
        externalDomains.add(hostname);
        rawReferences.push({ source: fullUrl, tag: el.tagName });
      }
    } catch (e) {}
  });

  if (externalDomains.size === 0) return;

  log(`          [*] Discovered ${externalDomains.size} unique external dependencies. Hunting for broken links...`);
  const limit = pLimit(SCANNER_CONFIG.concurrency);

  const tasks = Array.from(externalDomains).map(hostname => {
    return limit(async () => {
      await sleep(50, 150); 
      const isDead = await checkHostAvailability(hostname);
      
      if (isDead) {
        log(`          [!!!] CRITICAL SHADOW-TRUST ALERT: Abandoned Dependency Found!`);
        log(`                └─ Dead Host: ${hostname}`);
      } else {
        if (hostname.includes('s3.amazonaws.com') || hostname.endsWith('amazonaws.com')) {
          const isBucketClaimable = await checkS3Claimable(hostname);
          if (isBucketClaimable) {
            log(`          [!!!] CRITICAL S3 HIJACK ALERT: Orphaned Bucket Detected!`);
            log(`                └─ Bucket Name: ${hostname}`);
          }
        }

        const baseNameMatch = hostname.match(/^([^\.]+)\.([^\.]+)$/); 
        if (baseNameMatch) {
          const base = baseNameMatch[1];
          for (const tld of TLD_PERMUTATIONS) {
             const permutedHost = `${base}${tld}`;
             if (permutedHost === hostname) continue; 
             const isPermutationDead = await checkHostAvailability(permutedHost);
             if (isPermutationDead) {
               log(`          [!] TLD PERMUTATION RISK (Typo-Squatting possible): Target relies on ${hostname}, but ${permutedHost} is unregistered.`);
             }
          }
        }
      }
    });
  });

  await Promise.all(tasks);
  log(`          [*] Shadow-Trust Analysis complete.`);
}

async function bruteSubdomainsFromFile(domain, wildcardIp = null) {
  const path = 'subdomains.txt';
  if (!fs.existsSync(path)) return [];
  
  const words = fs.readFileSync(path, 'utf8').split('\n').map(w => w.trim()).filter(w => w && !w.startsWith('#'));
  log(`\n[*] Brute-forcing ${words.length} potential subdomains...`);
  
  const found = [];
  for (let i = 0; i < words.length; i += 20) {
    const chunk = words.slice(i, i + 20);
    const results = await Promise.all(chunk.map(sub => 
      dns.resolve4(`${sub}.${domain}`).then(ip => ({ sub: `${sub}.${domain}`, ip: ip[0] })).catch(() => null)
    ));

    results.forEach(r => { 
      if (r && (!wildcardIp || r.ip !== wildcardIp)) { 
        log(`  [+] Active: ${r.sub} (${r.ip})`); 
        found.push(r.sub); 
      } 
    });
  }
  return found;
}

async function fetchPageContent(targetUrl) {
  try {
    const response = await fetch(targetUrl, {
      headers: { 'User-Agent': BROWSER_PROFILES[0].ua },
      signal: AbortSignal.timeout(5000)
    });
    if (response.ok) return await response.text();
  } catch (err) {
    return null;
  }
  return null;
}

async function runContextFuzz(targetUrl) {
  log(`  [*] Fuzzing context: ${targetUrl}...`);
  
  const testPayloads = ['/admin', '/.env', '?debug=true', '?id=1\' OR 1=1'];
  
  for (const payload of testPayloads) {
      
  }
}

function extractLinks(html, baseUrl, targetDomain) {
  const $ = cheerio.load(html);
  const links = [];

  $('a[href]').each((_, el) => {
    let href = $(el).attr('href');
    try {
      const absoluteUrl = new URL(href, baseUrl).href;
      const parsed = new URL(absoluteUrl);

      if (
        parsed.hostname === targetDomain &&
        ['http:', 'https:'].includes(parsed.protocol) &&
        !href.startsWith('#') &&
        !/\.(png|jpg|jpeg|gif|pdf|zip|css|js)$/i.test(parsed.pathname)
      ) {
        links.push(absoluteUrl);
      }
    } catch (e) {
      
    }
  });

  return [...new Set(links)]; 
}

async function breadcrumbScan(startUrl, maxHops = 3) {
  let currentUrl = startUrl;
  const visited = new Set();
  const domain = new URL(startUrl).hostname;

  log(`\n[+] Starting Breadcrumb Crawl on: ${startUrl}`);

  for (let depth = 0; depth < maxHops; depth++) {
    log(`\n[Hop ${depth}] Context: ${currentUrl}`);
    visited.add(currentUrl);

    const html = await fetchPageContent(currentUrl);
    if (!html) {
      log(`  [-] Failed to retrieve content at ${currentUrl}. Ending trail.`);
      break;
    }

    await runContextFuzz(currentUrl);

    const links = extractLinks(html, currentUrl, domain);
    const nextLink = links.find(link => !visited.has(link));

    if (!nextLink) {
      log(`  [-] No more unique internal links found. Trail ended.`);
      break;
    }

    log(`  [>] Found link: ${nextLink}. Moving to next context...`);
    currentUrl = nextLink;
  }
}



function processCustomSignatures(customSigs) {
  const processed = {};
  
  for (const [tech, sig] of Object.entries(customSigs)) {
    processed[tech] = {};
    
    if (sig.dom && Array.isArray(sig.dom)) {
      processed[tech].dom = sig.dom.map(pattern => new RegExp(pattern, 'i'));
    }
    
    if (sig.headers) {
      processed[tech].headers = {};
      for (const [headerKey, pattern] of Object.entries(sig.headers)) {
        processed[tech].headers[headerKey.toLowerCase()] = new RegExp(pattern, 'i');
      }
    }
    
    if (sig.cookies && Array.isArray(sig.cookies)) {
      processed[tech].cookies = sig.cookies.map(pattern => new RegExp(pattern, 'i'));
    }
    
    if (sig.files && Array.isArray(sig.files)) {
      processed[tech].files = sig.files;
    }
  }
  return processed;
}


module.exports = {
  updateScannerConfig,
  lookupCVEs,
  identifyWAF,
  analyzeForHoneypot,
  scanInfrastructure,
  checkAnonymousFtp,
  checkRedisAuth,
  checkOpenRelay,
  checkSecurityHeaders,
  detectTechStack,
  fuzzWeb,
  advancedDiscoveryScan,
  crawlSitemap,
  scrapeJsForSecrets,
  analyzeShadowTrust,
  bruteSubdomainsFromFile,
  breadcrumbScan, 
  processCustomSignatures
};