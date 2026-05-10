const dns = require('node:dns').promises;
const net = require('node:net');
const tls = require('node:tls');
const https = require('node:https');
const http = require('node:http');
const dgram = require('node:dgram');


const DB_PROBES = {
  5432: Buffer.from([0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f]), 
  27017: Buffer.from([ 
    0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x13, 0x00, 0x00, 0x00, 0x10, 0x69, 0x73, 0x4d, 0x61,
    0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
  ]),
  1433: Buffer.from([ 
    0x12, 0x01, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
    0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03, 0x00, 0x28, 0x00, 0x04, 0xff, 0x08, 0x00, 0x01,
    0x55, 0x00, 0x00, 0x00, 0x4d, 0x53, 0x53, 0x51, 0x4c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x00
  ])
};

const UDP_PAYLOADS = {
  53: Buffer.from([0x24, 0x1a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01]), 
  123: Buffer.alloc(48).fill(0x1B, 0, 1), 
  161: Buffer.from([0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00]), 
  1900: Buffer.from('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n') 
};

const SMB_NEGOTIATE_PAYLOAD = Buffer.from([
  0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,             
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,             
  0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 
  0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02, 
  0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 
  0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 
  0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 
  0x32, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54, 
  0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00  
]);

const TAKEOVER_FINGERPRINTS = [
  { provider: 'GitHub Pages', cname: 'github.io', signature: /There isn't a GitHub Pages site here/i },
  { provider: 'AWS S3', cname: 's3.amazonaws.com', signature: /The specified bucket does not exist/i },
  { provider: 'Heroku', cname: 'herokuapp.com', signature: /No such app/i },
  { provider: 'Zendesk', cname: 'zendesk.com', signature: /Help Center Closed|Oops, this help center no longer exists/i },
  { provider: 'Shopify', cname: 'myshopify.com', signature: /Sorry, this shop is currently unavailable/i },
  { provider: 'Tumblr', cname: 'domains.tumblr.com', signature: /Whatever you were looking for doesn't currently exist at this address/i },
  { provider: 'Pantheon', cname: 'pantheonsite.io', signature: /The edg-echo-1 server you are communicating with is configured/i }
];




function extractVersion(str) {
  const match = str.match(/(\d+\.\d+(\.\d+)?(-[a-zA-Z0-9.]+)?)/);
  return match ? match[0] : 'Unknown';
}

async function stealthWrite(socket, buffer, chunkSize = 8, delay = 50) {
  socket.setNoDelay(true); 
  for (let i = 0; i < buffer.length; i += chunkSize) {
    const chunk = buffer.subarray(i, i + chunkSize);
    socket.write(chunk);
    if (i + chunkSize < buffer.length) {
      await new Promise(r => setTimeout(r, delay));
    }
  }
}



function parseServiceInfo(port, raw) {
  let info = { software: 'Unknown', version: 'Unknown', extra: [] };
  const firstLine = raw.split('\n')[0].trim();

  if ([80, 8080, 8888].includes(port)) {
    const lines = raw.split('\n');
    const serverLine = lines.find(l => l.toLowerCase().startsWith('server:'));
    const poweredBy = lines.find(l => l.toLowerCase().startsWith('x-powered-by:'));
    const titleMatch = raw.match(/<title>(.*?)<\/title>/i);
    
    if (titleMatch) info.extra.push(`Title: "${titleMatch[1]}"`);
    info.software = serverLine ? serverLine.split(':')[1].trim() : 'Web Server';
    info.version = extractVersion(info.software);
    if (poweredBy) info.extra.push(`Stack: ${poweredBy.split(':')[1].trim()}`);
  } 
  else if (port === 22) {
    const parts = firstLine.split('-');
    info.software = parts[2] ? parts[2].split('_')[0] : 'SSH';
    info.version = parts[2] ? parts[2].split('_')[1] : 'Unknown';
    if (firstLine.toLowerCase().includes('ubuntu')) info.extra.push('OS: Ubuntu');
    if (firstLine.toLowerCase().includes('debian')) info.extra.push('OS: Debian');
  } 
  else if (port === 21) {
    info.software = firstLine.replace('220', '').replace(/[()]/g, '').trim();
    info.version = extractVersion(info.software);
  } 
  else if (port === 25) {
    info.software = firstLine.includes('Postfix') ? 'Postfix' : (firstLine.includes('Exim') ? 'Exim' : 'SMTP');
    info.version = extractVersion(firstLine);
  } 
  else if (port === 3306) {
    const match = raw.match(/(\d+\.\d+\.\d+-[a-zA-Z0-9-]+)/);
    info.software = firstLine.toLowerCase().includes('mariadb') ? 'MariaDB' : 'MySQL';
    info.version = match ? match[0] : 'Unknown';
  } 
  else if ([110, 995].includes(port)) {
    info.software = 'POP3 Server';
    info.version = extractVersion(firstLine);
  }
  else if ([143, 993].includes(port)) {
    info.software = 'IMAP Server';
    info.version = extractVersion(firstLine);
  }
  else if (port === 587 || port === 465) {
    info.software = 'SMTP (Submission)';
    info.version = extractVersion(firstLine);
  }
  else {
    info.software = firstLine.substring(0, 60).replace(/[\r\x00-\x1F\x7F-\x9F]/g, "").trim() || 'Unknown Service';
  }

  return info;
}

function grabBanner(port, host) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let dataReceived = '';
    let isConnected = false; 
    socket.setTimeout(3000);

    socket.on('connect', () => {
      isConnected = true;
      if ([80, 8080, 8888].includes(port)) {
        socket.write(`GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
      } else if (port === 6379) {
        socket.write("INFO\r\n");
      }
    });

    socket.on('data', (chunk) => {
      dataReceived += chunk.toString('utf8');
      if (dataReceived.length > 4096) socket.destroy(); 
    });

    socket.on('timeout', () => socket.destroy());
    socket.on('error', () => resolve(null)); 
    
    socket.on('close', () => {
      if (!isConnected) return resolve(null);
      if (!dataReceived) return resolve({ port, open: true, banner: null });
      resolve({ port, open: true, banner: parseServiceInfo(port, dataReceived) });
    });

    socket.connect(port, host);
  });
}

function probeDatabase(port, host) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let dataReceived = Buffer.alloc(0);
    socket.setTimeout(3000);

    socket.on('connect', async () => {  
      const probe = DB_PROBES[port];
      if (probe) {
        await stealthWrite(socket, probe, 4, 20);
      } else {
        socket.destroy(); 
      }
    });

    socket.on('data', (chunk) => {
      dataReceived = Buffer.concat([dataReceived, chunk]);
      if (dataReceived.length > 1024) socket.destroy();
    });

    socket.on('close', () => {
      if (dataReceived.length === 0) return resolve(null);
      
      const raw = dataReceived.toString('utf8');
      let info = { software: 'Unknown DB', version: 'Unknown' };

      if (port === 5432) {
        info.software = 'PostgreSQL';
        const versionMatch = raw.match(/PostgreSQL ([\d.]+)/);
        if (versionMatch) info.version = versionMatch[1];
      } else if (port === 27017) {
        info.software = 'MongoDB';
        const versionMatch = raw.match(/"version"\s*:\s*"([\d.]+)"/);
        if (versionMatch) info.version = versionMatch[1];
      } else if (port === 1433) {
        info.software = 'MSSQL';
        if (dataReceived.includes('Microsoft SQL Server')) info.version = 'Detected';
      }

      if (info.version === 'Unknown') info.version = extractVersion(raw);

      resolve({ port, open: true, banner: info });
    });

    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });

    socket.connect(port, host);
  });
}

function probeSMB(host) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let dataReceived = Buffer.alloc(0);
    socket.setTimeout(4000);

    socket.on('connect', async () => { 
     await stealthWrite(socket, SMB_NEGOTIATE_PAYLOAD, 4, 20);
    });

    socket.on('data', (chunk) => {
      dataReceived = Buffer.concat([dataReceived, chunk]);
      if (dataReceived.length > 2048) socket.destroy();
    });

    socket.on('close', () => {
      if (dataReceived.length === 0) return resolve(null);
      
      const info = { software: 'SMB Service', version: 'Unknown' };
      const utf8 = dataReceived.toString('utf8');
      const utf16 = dataReceived.toString('utf16le');
      const osRegex = /(Windows\s[\d\.]+|Samba\s[\d\.]+)/i;
      const match = utf8.match(osRegex) || utf16.match(osRegex);

      if (match) {
        info.software = match[0].includes('Samba') ? 'Samba' : 'Windows';
        info.version = match[0];
      } else {
        info.version = extractVersion(utf8) !== 'Unknown' ? extractVersion(utf8) : 'Detected (Build Hidden)';
      }
      resolve({ port: 445, open: true, banner: info });
    });

    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });

    socket.connect(445, host);
  });
}

function probeUdpPort(port, host) {
  return new Promise((resolve) => {
    const client = dgram.createSocket('udp4');
    const payload = UDP_PAYLOADS[port] || Buffer.from([0x00]); 
    let found = false;

    client.on('message', (msg, rinfo) => {
      found = true;
      const data = msg.toString('utf8').replace(/[\r\n\x00-\x1F\x7F-\x9F]/g, " ").trim();
      client.close();
      resolve({ port, open: true, protocol: 'UDP', banner: data.substring(0, 50) });
    });

    client.on('error', () => {
      client.close();
      resolve(null);
    });

    client.send(payload, port, host, (err) => {
      if (err) {
        client.close();
        resolve(null);
      }
    });

    setTimeout(() => {
      if (!found) {
        client.close();
        resolve(null); 
      }
    }, 2000);
  });
}




async function smartResolve(domain) {
  try {
    const srvRecords = await dns.resolveSrv(`_minecraft._tcp.${domain}`);
    if (srvRecords && srvRecords.length > 0) {
      const srv = srvRecords[0];
      const srvIps = await dns.resolve4(srv.name).catch(() => []);
      if (srvIps.length > 0) {
        return { ip: srvIps[0], port: srv.port, method: 'SRV Record' };
      }
    }
  } catch (e) { }

  try {
    const ips = await dns.resolve4(domain);
    if (ips.length > 0) return { ip: ips[0], port: null, method: 'A Record' };
  } catch (e) { }

  try {
    const lookup = await dns.lookup(domain);
    if (lookup.address) return { ip: lookup.address, port: null, method: 'System Lookup' };
  } catch (e) { }

  return null;
}

async function detectWildcardDns(domain) {
  const randomSub = `sanity-check-${Math.random().toString(36).substring(2, 10)}.${domain}`;
  try {
    const ips = await dns.resolve4(randomSub);
    if (ips && ips.length > 0) return ips[0]; 
  } catch (err) {}
  return null;
}

async function getMailIntel(domain) {
  const mailResults = { mx: [], spf: null, dmarc: false };
  try {
    const mx = await dns.resolveMx(domain).catch(() => []);
    if (mx.length > 0) mailResults.mx = mx.sort((a, b) => a.priority - b.priority);

    const txt = await dns.resolveTxt(domain).catch(() => []);
    const spfRecord = txt.flat().find(r => r.startsWith('v=spf1'));
    if (spfRecord) mailResults.spf = spfRecord;

    const dmarc = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
    if (dmarc.length > 0) mailResults.dmarc = true;

    return mailResults;
  } catch (e) {
    return null;
  }
}

async function getDnsTxtIntel(domain, logger) {
  try {
    const records = await dns.resolveTxt(domain);
    const flattened = records.flat();
    
    if (flattened.length === 0) return [];

    const saasMarkers = {
      'Google Workspace': /google-site-verification/i,
      'Atlassian/Jira': /atlassian-domain-verification/i,
      'Microsoft 365': /MS=/i,
      'Adobe': /adobe-id-verification/i,
      'DocuSign': /docusign/i,
      'Facebook Business': /facebook-domain-verification/i,
      'HubSpot': /hubspot-verification/i,
      'Stripe': /stripe-verification/i
    };

    const results = [];
    flattened.forEach(rec => {
      let identified = false;
      for (const [provider, regex] of Object.entries(saasMarkers)) {
        if (regex.test(rec)) {
          results.push({ provider, record: rec });
          identified = true;
        }
      }
      if (!identified) {
        results.push({ provider: 'Unknown', record: rec });
      }
    });
    return results;
  } catch (err) {
    return [];
  }
}

async function attemptZoneTransfer(domain) {
  const results = [];
  try {
    const nameServers = await dns.resolveNs(domain);
    for (const ns of nameServers) {
      const isTcpOpen = await new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(2000);
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('error', () => resolve(false));
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.connect(53, ns);
      });

      results.push({ ns, isOpen: isTcpOpen });
    }
  } catch (err) {}
  return results;
}


async function getWhoisIntel(domain, options = {}) {
  try {
    const url = `https://www.rdap.net/domain/${domain}`;
    const response = await new Promise((resolve) => {
      https.get(url, { headers: { 'Accept': 'application/rdap+json' }, agent: options.torAgent }, (res) => {
        let data = '';
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      }).on('error', () => resolve({ status: 500 }));
    });

    if (response.status === 200) {
      const json = JSON.parse(response.body);
      let org = 'N/A';
      const registrant = json.entities?.find(e => e.roles?.includes('registrant'));
      if (registrant && registrant.vcardArray) {
         const orgItem = registrant.vcardArray[1].find(item => item[0] === 'org');
         if (orgItem) org = orgItem[3];
      }

      let creationDate = 'N/A';
      const regEvent = json.events?.find(e => e.eventAction === 'registration');
      if (regEvent) creationDate = regEvent.eventDate;

      const nameservers = json.nameservers?.map(ns => ns.ldhName.toLowerCase()) || [];

      return { source: 'RDAP', org, creationDate, nameservers };
    }
  } catch (e) {}

  
  try {
    const queryWhoisServer = (server, domain) => {
      return new Promise((resolve, reject) => {
        const client = net.connect(43, server, () => client.write(domain + '\r\n'));
        let data = '';
        client.setTimeout(5000);
        client.on('data', (chunk) => data += chunk);
        client.on('timeout', () => { client.destroy(); reject(new Error('Timeout')); });
        client.on('error', (err) => reject(err));
        client.on('end', () => resolve(data));
      });
    };

    const ianaResponse = await queryWhoisServer('whois.iana.org', domain);
    const referralMatch = ianaResponse.match(/whois:\s+([a-z0-9\.-]+)/i);
    let finalText = ianaResponse;
    if (referralMatch && referralMatch[1] && referralMatch[1] !== 'whois.iana.org') {
      finalText = await queryWhoisServer(referralMatch[1], domain);
    }
    
    let org = 'N/A', creationDate = 'N/A', nameservers = [];
    const orgMatch = finalText.match(/(?:Registrant Organization|org|Registrant):\s*(.*)/i);
    const dateMatch = finalText.match(/(?:Creation Date|created|Registration Date):\s*(.*)/i);
    const nsMatches = finalText.matchAll(/(?:Name Server|nserver):\s*([a-z0-9\.-]+)/gi);

    if (orgMatch) org = orgMatch[1].trim();
    if (dateMatch) creationDate = dateMatch[1].trim();
    for (const match of nsMatches) nameservers.push(match[1].toLowerCase());

    return { source: 'Legacy WHOIS', org, creationDate, nameservers };
  } catch (err) {
    return null;
  }
}



async function fetchHackerTarget(domain) {
  try {
    const response = await fetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
    const text = await response.text();
    if (!text || text.includes("error") || text.includes("API count exceeded")) return [];
    return text.split('\n').map(line => line.split(',')[0]);
  } catch (err) { return []; }
}

async function fetchWayback(domain) {
  try {
    const url = `https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=json&collapse=urlkey&fl=original&limit=1000`;
    const response = await fetch(url);
    const data = await response.json();
    const found = [];
    if (Array.isArray(data)) {
      for (let i = 1; i < data.length; i++) {
        try {
          const hostname = new URL(data[i][0]).hostname;
          if (hostname.endsWith(domain)) found.push(hostname);
        } catch (e) {}
      }
    }
    return found;
  } catch (err) { return []; }
}

async function fetchCrtSh(domain) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); 
    const response = await fetch(`https://crt.sh/?q=${domain}&output=json`, { signal: controller.signal });
    clearTimeout(timeoutId);
    const data = await response.json();
    const found = [];
    data.forEach(entry => {
      const names = entry.name_value.split('\n');
      names.forEach(name => {
        const cleanName = name.replace('*.', '').toLowerCase().trim();
        if (cleanName.endsWith(domain)) found.push(cleanName);
      });
    });
    return found;
  } catch (err) { return []; }
}

async function getPassiveSubdomains(domain) {
  const subdomains = new Set();
  const tasks = [fetchHackerTarget(domain), fetchWayback(domain), fetchCrtSh(domain)];
  const results = await Promise.allSettled(tasks);
  
  results.forEach((result) => {
    if (result.status === 'fulfilled' && result.value) {
      result.value.forEach(sub => subdomains.add(sub.toLowerCase().trim()));
    }
  });
  return Array.from(subdomains);
}

function verifyTakeoverSignature(host, signatureRegex, options = {}) {
  return new Promise((resolve) => {
    const reqOpts = { method: 'GET', timeout: 5000, rejectUnauthorized: false, agent: options.torAgent };
    const req = http.request(`http://${host}`, reqOpts, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve(signatureRegex.test(body)));
    });

    req.on('error', () => {
      const httpsReq = https.request(`https://${host}`, reqOpts, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve(signatureRegex.test(body)));
      });
      httpsReq.on('error', () => resolve(false));
      httpsReq.on('timeout', () => { httpsReq.destroy(); resolve(false); });
      httpsReq.end();
    });

    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

async function checkSubdomainTakeover(subdomain, options = {}) {
  try {
    const cnames = await dns.resolveCname(subdomain).catch(() => []);
    if (cnames.length === 0) return null;

    for (const cname of cnames) {
      const targetProvider = TAKEOVER_FINGERPRINTS.find(fp => cname.includes(fp.cname));
      if (targetProvider) {
        const isVulnerable = await verifyTakeoverSignature(subdomain, targetProvider.signature, options);
        return { vulnerable: isVulnerable, provider: targetProvider.provider, cname: cname };
      }
    }
    return null;
  } catch (err) { return null; }
}



function getTlsIntel(host, port) {
  return new Promise((resolve) => {
    const options = { host: host, port: port, servername: host, rejectUnauthorized: false, timeout: 5000 };
    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate();
      socket.destroy();
      if (!cert || Object.keys(cert).length === 0) return resolve({ success: false, error: 'No certificate found' });

      resolve({
        success: true,
        issuer: cert.issuer.O || cert.issuer.CN || 'Unknown',
        validTo: cert.valid_to,
        san: cert.subjectaltname || 'None'
      });
    });

    socket.on('error', (err) => resolve({ success: false, error: err.message }));
    socket.on('timeout', () => { socket.destroy(); resolve({ success: false, error: 'Connection Timeout' }); });
  });
}

module.exports = {
  grabBanner,
  probeDatabase,
  probeSMB,
  probeUdpPort,
  smartResolve,
  detectWildcardDns,
  getMailIntel,
  getDnsTxtIntel,
  attemptZoneTransfer,
  getWhoisIntel,
  getPassiveSubdomains,
  checkSubdomainTakeover,
  getTlsIntel
};