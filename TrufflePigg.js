#!/usr/bin/env node
const readline = require('node:readline');
const fs = require('node:fs');


const utils = require('./utils');
const sniffer = require('./sniffer');
const scanner = require('./scanner');
const network = require('./networker');
const data = require('./data');


const { log, clearSessionReport, getSessionReport, promptYesNo, setSleepConfig, getJson } = utils;


let SCAN_MODE = 'web';
let GLOBAL_BREADCRUMB_ENABLED = false;
let GLOBAL_BREADCRUMB_HOPS = 3;
let GLOBAL_FUZZ_DEPTH = 2;
let torAgent = undefined;
let PROXY_ROTATE_ENABLED = false;


const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});


function displayGuide() {
  console.log(`
=========================================================
          TrufflePigg
=========================================================
 TrufflePigg is a reconnaissance, fuzzing, and OSINT tool built in Node.js for domain and server(where the domain is hosted) analysis. It's designed to act as a Swiss Army knife for bug bounty hunters and penetration testers. It doesn't just scan ports; it sniffs out high-fidelity secrets, hunts for shadow-trust dependency takeovers, bypasses WAFs using HTTP/2 and Client Hints, and crawls deep into the application structure.

USAGE:
  TrufflePigg

COMMAND ARGUMENTS:
  --guide / --help / -h   Display this guide and exit.
  --mode [web|infra|both] Set the scan mode (Default: web).
  --ports [p1,p2,...]      Specify custom ports to scan.
  --breadcrumb             Enable breadcrumb crawling (internal link discovery).
  --hops [number]          Set max depth for breadcrumb crawling (Default: 3).
  --protate                Enable proxy rotation.
  --tor                    Enable tor routing (e.g. --tor socks5h://127.0.0.1:9050)
  --fuzzlist [path.txt]    Add a custom list for fuzzing.
  --concurrency [num]      Set maximum concurrent tasks (Default: 10).
  --depth [num]            Set web fuzzing/directory depth (Default: 2).
  --sleep [min,max]        Set random delay range in ms between requests.
  --signatures [path.json] Load custom technology detection signatures.

  Running the tool without arguments will use the default toolsets and settings.
=========================================================
  `);
}

function displayBanner() {
  const art1 = `
  --.--          ,---.,---.|         
    |  ,---..   .|__. |__. |    ,---.
    |  |    |   ||    |    |    |---'
    \`  \`    \`---'\`    \`    \`---'\`---'
    ,---.o
    |---'.,---.,---.  
    |    ||   ||   |
    \`    \`\`---|\`---|
          \`---'\`---'
`;
  const art2 = `
     __,---.__
  ,-'         \`-.__
&/           \`._\\ _\\
 /               ''._
 |   ,             (") -snorts-
 |__,'\`-..--|__|--''    
                          (-)
                            (+)
  `;
  console.log(art2); 
  console.log(art1);
  console.log("   Version 1.0 (Modularized) - Ready for sniffing...\n");
  console.log("================================================\n");
}


function parseCommandLineArgs() {
  const args = process.argv.slice(2);

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--guide' || args[i] === '--help' || args[i] === '-h') {
      displayGuide();
      process.exit(0);
    }
    else if (args[i] === '--ports' && args[i + 1]) {
      const customPorts = args[i + 1].split(',').map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p));
      if (customPorts.length > 0) {
        data.COMMON_PORTS.length = 0;
        data.COMMON_PORTS.push(...customPorts);
        console.log(`[*] Loaded ${data.COMMON_PORTS.length} custom ports from command line.`);
      } else {
        console.log(`[-] Invalid ports provided. Using defaults.`);
      }
      i++; 
    }
    else if (args[i] === '--breadcrumb') {
      GLOBAL_BREADCRUMB_ENABLED = true;
      console.log(`[*] Breadcrumb Crawling enabled.`);
    }
    else if (args[i] === '--hops') {
      const hopValue = parseInt(args[i + 1]);
      if (!isNaN(hopValue)) {
        GLOBAL_BREADCRUMB_HOPS = hopValue;
        console.log(`[*] Max Breadcrumb Hops set to: ${GLOBAL_BREADCRUMB_HOPS}`);
        i++; 
      }
    }
    else if (args[i] === '--protate') {
      PROXY_ROTATE_ENABLED = true;
      console.log(`[*] Proxy rotation enabled.`);
    }
    else if (args[i] === '--mode' && args[i + 1]) {
      const mode = args[i + 1].toLowerCase();
      if (['web', 'nonweb', 'infra', 'both'].includes(mode)) {
        SCAN_MODE = mode === 'nonweb' ? 'infra' : mode;
        console.log(`[*] Target Scan Mode configured to: ${SCAN_MODE.toUpperCase()}`);
      } else {
        console.log(`[-] Invalid mode provided. Use 'web', 'infra', or 'both'. Defaulting to web.`);
      }
      i++;
    }
    else if (args[i] === '--tor') {
      let proxyUrl = 'socks5h://127.0.0.1:9050'; 
      if (args[i + 1] && !args[i + 1].startsWith('--')) {
        proxyUrl = args[i + 1];
        i++; 
      }
      try {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        torAgent = new SocksProxyAgent(proxyUrl);
        scanner.updateScannerConfig({ torAgent });
        console.log(`[*] Tor proxy enabled via ${proxyUrl}`);
      } catch (err) {
        console.log(`[-] Failed to initialize Tor proxy: ${err.message}. (Ensure socks-proxy-agent is installed)`);
      }
    }
    else if (args[i] === '--fuzzlist' && args[i + 1]) {
      const wordlistPath = args[i + 1];
      if (fs.existsSync(wordlistPath)) {
        try {
          const content = fs.readFileSync(wordlistPath, 'utf8');
          const customFuzz = content.split(/\r?\n/).map(line => line.trim()).filter(line => line.length > 0 && !line.startsWith('#')); 
          if (customFuzz.length > 0) {
            data.FUZZ_TARGETS.length = 0;
            data.FUZZ_TARGETS.push(...customFuzz);
            console.log(`[*] Loaded ${data.FUZZ_TARGETS.length} targets from custom wordlist: ${wordlistPath}`);
          } else {
            console.log(`[-] Wordlist is empty. Using defaults.`);
          }
        } catch (err) {
          console.log(`[-] Error reading wordlist: ${err.message}`);
        }
      } else {
        console.log(`[-] Wordlist file not found: ${wordlistPath}. Using defaults.`);
      }
      i++; 
    }
    else if (args[i] === '--concurrency' && args[i + 1]) {
      const value = parseInt(args[i + 1], 10);
      if (!isNaN(value) && value > 0) {
        scanner.updateScannerConfig({ concurrency: value });
        console.log(`[*] Configured concurrency limit: ${value}`);
      } else {
        console.log(`[-] Invalid concurrency value. Using default.`);
      }
      i++; 
    }
    else if (args[i] === '--depth' && args[i + 1]) {
      const depth = parseInt(args[i + 1], 10);
      if (!isNaN(depth) && depth >= 0) {
        GLOBAL_FUZZ_DEPTH = depth;
        scanner.updateScannerConfig({ fuzzDepth: depth });
        console.log(`[*] Configured fuzzing depth: ${depth}`);
      } else {
        console.log(`[-] Invalid depth provided. Using default (2).`);
      }
      i++; 
    }
    else if (args[i] === '--signatures' && args[i + 1]) {
      const sigPath = args[i + 1];
      if (fs.existsSync(sigPath)) {
        try {
          const content = fs.readFileSync(sigPath, 'utf8');
          const customSigs = JSON.parse(content);
          const processedSigs = scanner.processCustomSignatures(customSigs);
          Object.assign(data.TECH_SIGNATURES_PRO, processedSigs);
          console.log(`[*] Loaded ${Object.keys(processedSigs).length} custom technology signatures from: ${sigPath}`);
        } catch (err) {
          console.log(`[-] Error reading or parsing signatures JSON: ${err.message}`);
        }
      } else {
        console.log(`[-] Signatures file not found: ${sigPath}. Using defaults.`);
      }
      i++; 
    }
    else if (args[i] === '--sleep' && args[i + 1]) {
      const parts = args[i + 1].split(',').map(p => parseInt(p.trim(), 10));
      if (parts.length === 2 && !parts.some(isNaN)) {
        setSleepConfig(parts[0], parts[1]);
        console.log(`[*] Configured global sleep range: ${parts[0]}ms - ${parts[1]}ms`);
      } else {
        console.log(`[-] Invalid sleep format. Use: --sleep min,max`);
      }
      i++;
    }
  }
}


async function fetchIntel(input) {
  clearSessionReport(); 
  log(`\n========================================`);
  log(`[*] TARGET: ${input}`);
  log(`========================================`);
  
  scanner.updateScannerConfig({ rl: rl });
  
  const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(input);
  const isDomain = !isIp;
  
  if (PROXY_ROTATE_ENABLED) {
    const pCount = await network.refreshProxyList();
    if (pCount > 0) log(`[*] Loaded ${pCount} proxies into rotation pool.`);
    
    const proxyInfo = network.rotateProxy();
    if (proxyInfo) {
      try {
        const { SocksProxyAgent } = require('socks-proxy-agent');
        const proxyUrl = `socks5://${proxyInfo.host}:${proxyInfo.port}`;

        torAgent = new SocksProxyAgent(proxyUrl);
        scanner.updateScannerConfig({ torAgent });
        log(`[*] IP Masking Active: Using proxy ${proxyUrl}`);
      } catch (err) {
        log(`[-] Error setting up rotation proxy: ${err.message}. (Ensure socks-proxy-agent is installed)`);
      }
    }
  }
  
  if (isDomain) {
    log(`\n--- [ WHOIS ENRICHMENT ] ---`);
    const whoisInfo = await sniffer.getWhoisIntel(input, { torAgent });
    if (whoisInfo) {
      log(`  [+] Organization: ${whoisInfo.org}`);
      log(`  [+] Created On  : ${whoisInfo.creationDate}`);
      log(`  [+] Nameservers : ${whoisInfo.nameservers.join(', ')}`);
      log(`  [+] Source: ${whoisInfo.source}`);
    } else {
      log(`  [-] All WHOIS methods failed.`);
    }
    
    log(`\n--- [ DNS INTELLIGENCE ] ---`);
    const wildcardIp = await sniffer.detectWildcardDns(input);
    if (wildcardIp) {
      log(`  [!] WARNING: Wildcard DNS detected! (${wildcardIp})`);
      log(`      Subdomains resolving to this IP will be ignored to ensure precision.`);
    } else {
      log(`  [+] No Wildcard DNS detected. Precision mode: High.`);
    }

    log(`\n[*] Scanning DNS TXT Records for SaaS Fingerprints...`);
    const txtRecords = await sniffer.getDnsTxtIntel(input);
    if (txtRecords.length === 0) log(`  [-] No TXT records found.`);
    txtRecords.forEach(r => {
      if (r.provider !== 'Unknown') {
        log(`  [!] IDENTIFIED SaaS: ${r.provider}`);
        log(`      └─ Record: ${r.record}`);
      } else {
        log(`  [+] TXT Record: ${r.record.substring(0, 80)}${r.record.length > 80 ? '...' : ''}`);
      }
    });

    log(`\n[*] Checking for AXFR (Zone Transfer) Vulnerabilities...`);
    const axfrRecords = await sniffer.attemptZoneTransfer(input);
    if (axfrRecords.length === 0) log(`  [-] Could not resolve Name Servers for AXFR.`);
    axfrRecords.forEach(r => {
      log(`  [*] Attempting AXFR on: ${r.ns}...`);
      if (r.isOpen) {
        log(`      [!] TCP Port 53 OPEN. Potential for Zone Transfer.`);
        log(`          [Manual Check]: dig axfr @${r.ns} ${input}`);
      } else {
        log(`      [-] TCP Port 53 closed on ${r.ns}. AXFR unlikely.`);
      }
    });
  }
  
  try {
    let targetIp = input;
    let targetPorts = [...data.COMMON_PORTS];

    if (isDomain) {
      log(`[*] Resolving domain...`);
      const resolution = await sniffer.smartResolve(input);

      if (resolution) {
        targetIp = resolution.ip;
        log(`  [+] Resolved via ${resolution.method}: ${targetIp}`);
        
        if (resolution.port && !targetPorts.includes(resolution.port)) {
          log(`  [+] Custom Port detected: ${resolution.port}`);
          targetPorts.push(resolution.port);
        }
      
        log(`\n[*] Querying Passive Sources Concurrently...`);
        const discoveredSubdomains = await sniffer.getPassiveSubdomains(input);
        if (discoveredSubdomains.length > 0) {
          discoveredSubdomains.forEach(s => log(`  [+] Found: ${s}`));
          log(`\n[*] Checking ${discoveredSubdomains.length} subdomains for takeover vulnerabilities...`);
          
          let takeoverFound = false;
          for (const sub of discoveredSubdomains) {
            const takeoverResult = await sniffer.checkSubdomainTakeover(sub, { torAgent });
            if (takeoverResult) {
              if (takeoverResult.vulnerable) {
                log(`  [!!!] CRITICAL: Subdomain Takeover Possible!`);
                log(`        └─ Target:   ${sub}`);
                log(`        └─ Provider: ${takeoverResult.provider}`);
                log(`        └─ CNAME:    ${takeoverResult.cname}`);
                takeoverFound = true;
              } else {
                log(`  [i] Notice: ${sub} points to ${takeoverResult.provider} (${takeoverResult.cname}) but appears actively claimed.`);
              }
            }
          }
          if (!takeoverFound) log(`  [-] No vulnerable CNAME configurations detected.`);
        } else {
          log(`  [-] No subdomains found in passive sources.`);
        }

        log(`\n[*] Checking Mail Configuration...`);
        const mailInfo = await sniffer.getMailIntel(input);
        if (mailInfo && mailInfo.mx.length > 0) {
          log(`  [+] MX Records:`);
          mailInfo.mx.forEach(m => log(`      - ${m.exchange} (Priority: ${m.priority})`));
          if (mailInfo.spf) log(`  [+] SPF Record: ${mailInfo.spf.substring(0, 50)}...`);
          if (mailInfo.dmarc) log(`  [+] DMARC: Configured`);
        } else {
          log(`  [-] No MX records found.`);
        }
      } else {
        log(`  [!] Could not resolve "${input}" to an IPv4 address.`);
        return ask();
      }
    }
   
    log(`\n[*] Fetching Geo/ISP...`);
    try {
      const intel = await getJson(`https://ipwho.is/${targetIp}`);
      if (intel && intel.success) {
        log(`  [+] Location: ${intel.city}, ${intel.country} (${intel.country_code})`);
        log(`  [+] ISP:      ${intel.connection.isp}`);
        log(`  [+] ASN:      AS${intel.connection.asn}`);
        
        if (intel.security.proxy || intel.security.vpn || intel.security.tor) {
          let tags = [];
          if (intel.security.proxy) tags.push('Proxy');
          if (intel.security.vpn) tags.push('VPN');
          if (intel.security.tor) tags.push('Tor');
          log(`  [!] Security Warning: Source identified as ${tags.join('/')}`);
        }
      } else {
        log(`  [-] API Error: ${intel.message}`);
      }
    } catch (err) {
      log(`  [!] Geo API Connection Error.`);
    }

    log(`\n[*] Scanning ${targetPorts.length} Ports...`);
    const scanPromises = targetPorts.map(port => sniffer.grabBanner(port, targetIp));
    const scanResults = await Promise.all(scanPromises);
    const openPorts = scanResults.filter(r => r !== null && r.open);

    log(`\n[*] Running Heuristic Analysis...`);
    const honeypotIssues = scanner.analyzeForHoneypot(openPorts);
    if (honeypotIssues.length > 0) {
      log(`  [!] WARNING: Potential Honeypot/IDS detected!`);
      honeypotIssues.forEach(issue => log(`      └─ ${issue}`));
    } else {
      log(`  [+] No obvious honeypot signatures found.`);
    }

    if (openPorts.length > 0) {
      openPorts.sort((a, b) => a.port - b.port).forEach(r => {
        let output = `  [+] Port ${r.port.toString().padEnd(5)} open`;
        if (r.banner) {
          output += ` -> ${r.banner.software} (v: ${r.banner.version})`;
          if (r.banner.extra.length > 0) {
            output += ` | ${r.banner.extra.join(', ')}`;
          }
        }
        log(output);
      });

      log(`\n[*] Checking for known vulnerabilities (CVEs)...`);
      for (const r of openPorts) {
        if (!r.banner) {
          log(`  [-] Port ${r.port}: No banner grabbed, skipping CVE check.`);
          continue;
        }

        const software = r.banner.software;
        const version = r.banner.version;

        if (software === 'Unknown' || software === 'Web Server' || version === 'Unknown') {
          log(`  [-] Port ${r.port}: Insufficient version data (${software} v: ${version}), skipping.`);
          continue;
        }

        log(`  [*] Querying NIST NVD for ${software} ${version}...`);
        await new Promise(resolve => setTimeout(resolve, 2000)); 
        const cves = await scanner.lookupCVEs(software, version);
        
        if (cves && cves.error) {
           log(`      [-] ${cves.error}`);
        } else if (cves && cves.length > 0) {
          cves.forEach(cve => {
            const severityPrefix = cve.score >= 7.0 ? '[!]' : '[+]';
            log(`      ${severityPrefix} ${cve.id} (CVSS: ${cve.score} - ${cve.severity})`);
            log(`          └─ ${cve.description}`);
          });
        } else {
          log(`      [-] No known CVEs found in database for this specific version.`);
        }
      }

      
      if (SCAN_MODE === 'web' || SCAN_MODE === 'both') {
        let webPorts = openPorts.map(r => r.port).filter(p => [80, 443, 8080, 8443, 8888].includes(p));

        if (webPorts.includes(443)) webPorts = webPorts.filter(p => p !== 80);
        if (webPorts.includes(8443)) webPorts = webPorts.filter(p => p !== 8080);
        
        if (webPorts.length > 0) {
          log(`\n[*] Analyzing HTTP Security Headers...`);
          for (const webPort of webPorts) {
            const headerIntel = await scanner.checkSecurityHeaders(input, webPort);
            if (headerIntel.success) {
              log(`  [+] Port ${webPort} Header Config:`);
              Object.entries(headerIntel.data).forEach(([header, value]) => {
                if (value) {
                  if (header === 'Content-Security-Policy') {
                    log(`      [!] ${header}:`);
                    log(`          ${value.split(';').join(';\n          ')}`); 
                  } else {
                    log(`      [+] ${header}: ${value}`);
                  }
                } else {
                  log(`      [-] ${header}: MISSING`);
                }
              });
            } else {
              log(`  [-] Port ${webPort}: Failed to fetch headers (${headerIntel.error})`);
            }

            if (webPort === 443 || webPort === 8443) {
              log(`\n      [*] TLS/SSL Certificate Intel:`);
              const sslIntel = await sniffer.getTlsIntel(input, webPort);

              if (sslIntel.success) {
                log(`          [+] Issuer:     ${sslIntel.issuer}`);
                log(`          [+] Expires:    ${sslIntel.validTo}`);
                const sanList = sslIntel.san.split(', ').map(s => s.replace('DNS:', ''));
                log(`          [+] SAN:        ${sanList.slice(0, 5).join(', ')}`);
                if (sanList.length > 5) log(`                          ...and ${sanList.length - 5} more`);
                
                const expiryDate = new Date(sslIntel.validTo);
                if (expiryDate < new Date()) {
                  log(`          [!] WARNING: Certificate is EXPIRED`);
                }
              } else {
                log(`          [-] SSL Check Failed: ${sslIntel.error}`);
              }
            }

            const techIntel = await scanner.detectTechStack(input, webPort);
            if (techIntel.success) {
              if (techIntel.stack.length > 0) {
                log(`      [*] Detected Technologies:`);
                log(`          => ${techIntel.stack.join(', ')}`);
              } else {
                log(`      [*] Detected Technologies: None identified`);
              }
            } else {
              log(`      [-] Failed to fingerprint HTML: ${techIntel.error}`);
            }

            await scanner.advancedDiscoveryScan(input, webPort);
            await scanner.fuzzWeb(input, webPort, '/', 0, GLOBAL_FUZZ_DEPTH);
            await scanner.scrapeJsForSecrets(input, webPort);
            await scanner.analyzeShadowTrust(input, webPort);

            const isHttps = webPort === 443 || webPort === 8443;
            const constructedUrl = `${isHttps ? 'https' : 'http'}://${input}:${webPort}`;
            
            if (GLOBAL_BREADCRUMB_ENABLED) {
              await scanner.breadcrumbScan(constructedUrl, GLOBAL_BREADCRUMB_HOPS);
            } else {
              log(`      [*] Breadcrumb Crawling is disabled. Use --breadcrumb to enable.`);
            }
          }
        }
      }

      
      if (SCAN_MODE === 'infra' || SCAN_MODE === 'both') {
         await scanner.scanInfrastructure(targetIp);
      }
    } else {
      log(`  [-] No open ports detected.`);
    }

  } catch (err) {
    log(`\n[!] Fatal Error: ${err.message}`);
  }
  
  log(`========================================\n`);

  
  const wantToSave = await promptYesNo(rl, `[?] Scan complete. Download full report to .txt? (y/n): `);

  if (wantToSave === 'y' || wantToSave === 'yes') {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const safeHost = input.replace(/[^a-z0-9]/gi, '_');
    const filename = `recon_${safeHost}_${timestamp}.txt`;

    try {
      fs.writeFileSync(filename, getSessionReport());
      console.log(`[+] SUCCESS: Full report saved to ./${filename}`);
    } catch (err) {
      console.log(`[-] ERROR: Could not save file: ${err.message}`);
    }
  } else {
    console.log(`[*] Report discarded.`);
  }
  
  ask();
}


function ask() {
  rl.question('Enter target (or "exit" to quit, "guide" for help): ', (answer) => {
    const input = answer.trim();
    const cmd = input.toLowerCase();

    if (cmd === 'exit' || cmd === 'quit') {
      console.log('Exiting...');
      rl.close();
      process.exit(0); 
    }

    if (cmd === 'guide' || cmd === '--guide' || cmd === 'help') {
      console.clear();
      displayGuide(); 
      return ask();   
    }

    if (input) {
      fetchIntel(input);
    } else {
      ask(); 
    }
  });
}


console.clear();
parseCommandLineArgs();
displayBanner();
ask();