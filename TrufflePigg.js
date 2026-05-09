#!/usr/bin/env node
const { URL } = require('node:url');
let GLOBAL_ROTATE_ENABLED = false;
const tls = require('node:tls');
const pLimit = require('p-limit');
const cheerio = require('cheerio');
const dns = require('node:dns').promises;
const https = require('node:https');
const readline = require('node:readline');
let torAgent = undefined;
 let PROXY_LIST = [];
const http = require('node:http');
const net = require('node:net');
const fs = require('node:fs');
const dgram = require('node:dgram');
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});
 
 const { SocksClient } = require('socks');
const http2 = require('node:http2');
const {
  HTTP2_HEADER_PATH,
  HTTP2_HEADER_METHOD,
  HTTP2_HEADER_AUTHORITY,
  HTTP2_HEADER_SCHEME,
  HTTP2_HEADER_USER_AGENT,
  HTTP2_HEADER_ACCEPT
} = http2.constants;
 let CURRENT_PROXY_INFO = null;
const BROWSER_PROFILES = [
  {
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ch: {
      "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
      "sec-ch-ua-platform-version": '"15.0.0"',
      "sec-ch-ua-arch": '"x86"',
      "sec-ch-ua-bitness": '"64"'
    }
  },
  {
    ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    ch: {
      "sec-ch-ua": '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Linux"',
      "sec-ch-ua-platform-version": '""'
    }
  },
  {
    ua: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    ch: {
      "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
      "sec-ch-ua-mobile": "?1",
      "sec-ch-ua-platform": '"Android"',
      "sec-ch-ua-model": '"Pixel 7"'
    }
  }
];
function getHumanHeaders(targetUrl) {
  const profile = BROWSER_PROFILES[Math.floor(Math.random() * BROWSER_PROFILES.length)];
  const urlObj = new URL(targetUrl);

  const headers = {
    "user-agent": profile.ua,
    ...profile.ch,
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate, br, zstd",
    "cache-control": "max-age=0",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none", 
    "sec-fetch-user": "?1",
    "upgrade-insecure-requests": "1",
    "referer": "https://www.google.com/",
    "dnt": "1"
  };


  headers["sec-ch-ua-full-version-list"] = profile.ch["sec-ch-ua"].replace(/v="\d+"/g, 'v="124.0.6367.201"');

  return headers;
}

 async function stealthFetch(targetUrl) {
  return new Promise((resolve, reject) => {
    const url = new URL(targetUrl);
    const humanHeaders = getHumanHeaders(targetUrl);
    

    const client = http2.connect(url.origin, {

      settings: {
        enablePush: false,
        initialWindowSize: 6291456,
        maxFrameSize: 16384,
      }
    });

    client.on('error', (err) => {

      reject(err);
    });


    const req = client.request({
      [HTTP2_HEADER_METHOD]: 'GET',
      [HTTP2_HEADER_PATH]: url.pathname + url.search,
      [HTTP2_HEADER_SCHEME]: 'https',
      [HTTP2_HEADER_AUTHORITY]: url.hostname,
     ...humanHeaders, 
      [HTTP2_HEADER_ACCEPT]: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
      'accept-language': 'en-US,en;q=0.5',
      'accept-encoding': 'gzip, deflate, br',
      'upgrade-insecure-requests': '1',
      'sec-fetch-dest': 'document',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-site': 'none',
      'sec-fetch-user': '?1',
    });

    let data = '';
    req.on('response', (headers, flags) => {

    });

    req.setEncoding('utf8');
    req.on('data', (chunk) => { data += chunk; });
    
    req.on('end', () => {
      client.close();
      resolve(data);
    });

    req.end();
  });
}


let sessionReport = "";


function log(...args) {
  const message = args.join(' ');
  console.log(message);
  sessionReport += message + "\n";
}

let GLOBAL_MIN_SLEEP = 100;
let GLOBAL_MAX_SLEEP = 500;

let GLOBAL_FUZZ_DEPTH = 2; 
let COMMON_PORTS = [
  21, 22, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 6379, 8080, 8888, 25565
];
let GLOBAL_CONCURRENCY = 10;
let limit;
let FUZZ_TARGETS = [
 
  '.env', '.git/config', '.htaccess', 'phpinfo.php', 'config.php', 
  'wp-config.php', 'backup.zip', 'login.php', 'docker-compose.yml', 
  'server-status', '.ssh/id_rsa', '.aws/credentials', 'composer.json',
  

  'admin/', 'api/', 'api/v1/', 'wp-json/wp/v2/users/', 'backup/', 'config/', 'dev/'
];
 let GLOBAL_BREADCRUMB_ENABLED = false;
 let GLOBAL_BREADCRUMB_HOPS = 3;
let SCAN_MODE = 'web'; 

const MAIL_PORTS = [25, 110, 143, 465, 587, 993, 995];
const DB_PORTS = [3306, 5432, 6379, 27017];
const ADMIN_PORTS = [21, 22, 3389, 445];
const INFRA_PORTS = [...MAIL_PORTS, ...DB_PORTS, ...ADMIN_PORTS];

const TLD_PERMUTATIONS = ['.com', '.net', '.org', '.io', '.co', '.dev', '.app', '.xyz'];
const WHITELIST_DOMAINS = [
  'google.com', 'google-analytics.com', 'facebook.com', 'twitter.com',
  'youtube.com', 'linkedin.com', 'fonts.googleapis.com', 'cloudflare.com',
  'github.com', 'w3.org', 'schema.org', 'googletagmanager.com', 'unpkg.com',
  'jsdelivr.net', 'cdnjs.cloudflare.com'
];
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
 const COMMON_UDP_PORTS = [53, 67, 68, 123, 161, 162, 1900, 5353];
 const UDP_PAYLOADS = {
  53: Buffer.from([0x24, 0x1a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01]), 
  123: Buffer.alloc(48).fill(0x1B, 0, 1), 
  161: Buffer.from([0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00]), 
  1900: Buffer.from('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n') 
};

const SMB_NEGOTIATE_PAYLOAD = Buffer.from([
  0x00, 0x00, 0x00, 0x85, 
  0xff, 0x53, 0x4d, 0x42,
  0x72,                   
  0x00, 0x00, 0x00, 0x00, 
  0x18,                   
  0x53, 0xc8,             
  0x00, 0x00,             
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00,             
  0x00, 0x00,             
  0xff, 0xfe,             
  0x00, 0x00,             
  0x00, 0x00,             
  0x00,                   
  0x62, 0x00,              
  0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00,
  0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00,
  0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00,
  0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00,
  0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00,
  0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00  
]);
 async function refreshProxyList() {
  log(`[*] Fetching fresh proxy list for rotation...`);
  try {

    const response = await fetch('https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all');
    const text = await response.text();
    PROXY_LIST = text.split(/\r?\n/).filter(p => p.trim().length > 0);
    
    if (PROXY_LIST.length > 0) {
      log(`  [+] Loaded ${PROXY_LIST.length} proxies into the rotation pool.`);
    } else {
      log(`  [-] Proxy list was empty. Falling back to direct connection.`);
    }
  } catch (err) {
    log(`  [-] Failed to fetch proxy list: ${err.message}`);
  }
}



function displayGuide() {
  console.log(`
=========================================================
          TrufflePigg
=========================================================
TrufflePigg is a recon and fuzzing tool 
designed for domain and server reconnaissance(enough of an explanation i guess).

USAGE:
  trufflepig(bruh then how did you get to here)

COMMAND ARGUMENTS:
  --guide / --help / -h   Display this guide and exit(what else do you think it'll do).
  --mode [web|nonweb|both] Set the scan mode (Default: web).
  --ports [p1,p2,...]      Specify custom ports to scan.
  --breadcrumb             Enable breadcrumb crawling (internal link discovery).
  --hops [number]          Set max depth for breadcrumb crawling (Default: 3).
  --protate                Enable proxy rotation.
  --tor                    Enable tor routing(needs the daemon to be already installed)
  --fuzzlist [path.txt]    lets do you add a custom list for fuzzing
  --concurrency [num]      Set maximum concurrent tasks (Default: 10).
  --depth [num]            Set web fuzzing/directory depth (Default: 2).
  --sleep [min,max]        Set random delay range in ms between requests.
  --signatures [path.json] Load custom technology detection signatures.

  Running the tool without arguments will let the tool use the default toolsets and settings.
=========================================================
  `);
}
async function breadcrumbScan(startUrl, maxHops = 3) {
  let currentUrl = startUrl;
  const visited = new Set();
  const domain = new URL.URL(startUrl).hostname;

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


function extractLinks(html, baseUrl, targetDomain) {
  const $ = cheerio.load(html);
  const links = [];

  $('a[href]').each((_, el) => {
    let href = $(el).attr('href');
    try {

      const absoluteUrl = new URL.URL(href, baseUrl).href;
      const parsed = new URL.URL(absoluteUrl);


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


async function runContextFuzz(targetUrl) {
  log(`  [*] Fuzzing context: ${targetUrl}...`);
  
  
  const testPayloads = ['/admin', '/.env', '?debug=true', '?id=1\' OR 1=1'];
  
  for (const payload of testPayloads) {

  }
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
 async function stealthFetchH2(targetUrl) {
  return new Promise(async (resolve, reject) => {
    const url = new URL(targetUrl);
    let socket;

    try {

      if (CURRENT_PROXY_INFO || torAgent) {
        const proxy = CURRENT_PROXY_INFO || { host: '127.0.0.1', port: 9050 };
        const info = await SocksClient.createConnection({
          proxy: { host: proxy.host, port: proxy.port, type: 5 },
          command: 'connect',
          destination: { host: url.hostname, port: parseInt(url.port) || 443 }
        });
        socket = info.socket;
      }


      const client = http2.connect(url.origin, {
        createConnection: () => {

          if (socket) return tls.connect({
            socket: socket,
            servername: url.hostname,
            ALPNProtocols: ['h2']
          });
          return tls.connect(parseInt(url.port) || 443, url.hostname, { ALPNProtocols: ['h2'] });
        },
        settings: { enablePush: false, initialWindowSize: 6291456 }
      });

      client.on('error', (err) => reject(err));


      const req = client.request({
        [HTTP2_HEADER_METHOD]: 'GET',
        [HTTP2_HEADER_PATH]: url.pathname + url.search,
        [HTTP2_HEADER_SCHEME]: url.protocol.replace(':', ''),
        [HTTP2_HEADER_AUTHORITY]: url.hostname,
        [HTTP2_HEADER_USER_AGENT]: getHumanHeaders(targetUrl),
        ...getWafEvasionHeaders(), 
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.5'
      });

      let data = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => { data += chunk; });
      req.on('end', () => {
        client.close();
        resolve(data);
      });
      req.end();

    } catch (err) {
      reject(err);
    }
  });
}
 /**
 * 
 * @param {net.Socket} socket 
 * @param {Buffer} buffer 
 * @param {number} chunkSize 
 * @param {number} delay 
 */
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
 function rotateProxy() {
  if (PROXY_LIST.length === 0) return;

  const randomIndex = Math.floor(Math.random() * PROXY_LIST.length);
  const proxy = PROXY_LIST[randomIndex];
  const [host, port] = proxy.split(':');
  
  try {
    const { SocksProxyAgent } = require('socks-proxy-agent');
    const proxyUrl = `socks5://${host}:${port}`;
    CURRENT_PROXY_INFO = { host, port: parseInt(port) };
    torAgent = new SocksProxyAgent(proxyUrl);
    log(`[*] IP Masking Active: Using proxy ${proxyUrl}`);
  } catch (err) {
    log(`[-] Error rotating proxy: ${err.message}. Ensure 'socks-proxy-agent' is installed.`);
  }
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
      
      const info = parseSmbResponse(dataReceived);
      resolve({ port: 445, open: true, banner: info });
    });

    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });

    socket.connect(445, host);
  });
}


function parseSmbResponse(buffer) {
  const info = { software: 'SMB Service', version: 'Unknown' };
  

  const utf8 = buffer.toString('utf8');
  const utf16 = buffer.toString('utf16le');


  const osRegex = /(Windows\s[\d\.]+|Samba\s[\d\.]+)/i;
  const match = utf8.match(osRegex) || utf16.match(osRegex);

  if (match) {
    info.software = match[0].includes('Samba') ? 'Samba' : 'Windows';
    info.version = match[0];
  } else {

    info.version = extractVersion(utf8) !== 'Unknown' ? extractVersion(utf8) : 'Detected (Build Hidden)';
  }

  return info;
}

let TECH_SIGNATURES_PRO = {

  'WordPress': {
    dom: [
      /wp-content\/themes/i, 
      /wp-includes\/js/i, 
      /<meta name="generator" content="WordPress/i,
      /<link rel="https:\/\/api\.w\.org\/"/i
    ],
    headers: { 'link': /<[^>]+rest_route=\/>/i },
    cookies: [/wp-settings-[0-9]+/i, /wordpress_logged_in_/i, /wordpress_test_cookie/i],
    files: ['/wp-login.php', '/wp-admin/admin-ajax.php', '/xmlrpc.php', '/license.txt', '/readme.html']
  },
  'Drupal': {
    dom: [
      /Drupal\.settings/i, 
      /sites\/default\/files/i, 
      /<meta name="Generator" content="Drupal/i,
      /data-drupal-link-system-path/i
    ],
    headers: { 'x-generator': /Drupal/i, 'x-drupal-cache': /.*/i, 'x-drupal-dynamic-cache': /.*/i },
    files: ['/core/install.php', '/CHANGELOG.txt', '/user/login']
  },
  'Joomla': {
    dom: [
      /<meta name="generator" content="Joomla!/i, 
      /Joomla\.options/i,
      /components\/com_/i
    ],
    headers: { 'x-content-encoded-by': /Joomla/i },
    cookies: [/joomla_user_state/i, /[a-f0-9]{32}/i], 
    files: ['/administrator/index.php', '/language/en-GB/en-GB.xml', '/README.txt']
  },
  'Magento': {
    dom: [
      /mage\/cookies/i, 
      /text\/x-magento-init/i,
      /skin\/frontend\//i
    ],
    headers: { 'x-magento-cache-id': /.*/i, 'x-magento-tags': /.*/i },
    cookies: [/frontend/i, /store/i, /adminhtml/i],
    files: ['/magento_version', '/pub/static/deployed_version.txt', '/app/etc/env.php'] 
  },
  'Shopify': {
    dom: [
      /cdn\.shopify\.com/i, 
      /Shopify\.theme/i,
      /window\.ShopifyAnalytics/i
    ],
    headers: { 'x-shopid': /.*/i, 'x-shardid': /.*/i },
    cookies: [/_secure_session_id/i, /_shopify_s/i, /_shopify_y/i]
  },
  'Ghost': {
    dom: [
      /<meta name="generator" content="Ghost/i,
      /ghost-sdk\.min\.js/i
    ],
    headers: { 'x-ghost-cache-status': /.*/i },
    files: ['/ghost/api/v3/content/', '/ghost/']
  },


  'Next.js': {
    dom: [
      /__NEXT_DATA__/i, 
      /<script[^>]+src="[^"]*\/_next\//i,
      /next-head-count/i
    ],
    headers: { 'x-powered-by': /Next\.js/i },
    files: ['/_next/static/chunks/main.js', '/_next/static/css/']
  },
  'React': {
    dom: [
      /data-reactroot/i, 
      /__REACT_DEVTOOLS_GLOBAL_HOOK__/i,
      /<div id="root">/i 
    ]
  },
  'Vue.js': {
    dom: [
      /data-v-[a-z0-9]{8}/i, 
      /__VUE__/i, 
      /vue-app/i
    ]
  },
  'Nuxt.js': {
    dom: [
      /__NUXT__/i,
      /_nuxt\//i
    ],
    headers: { 'x-nuxt-version': /.*/i }
  },
  'Angular': {
    dom: [
      /ng-app/i, 
      /ng-version/i, 
      /_ngcontent-/i, 
      /ng-reflect-/i
    ]
  },
  'Svelte': {
    dom: [
      /__svelte-meta/i,
      /svelte-[a-z0-9]{6}/i
    ]
  },
  'Bootstrap': {
    dom: [
      /bootstrap(\.bundle)?(\.min)?\.js/i,
      /bootstrap(\.min)?\.css/i,
      /class="[^"]*col-md-[0-9]/i
    ]
  },
  'Tailwind CSS': {
    dom: [
      /tailwind/i,
      /class="[^"]*text-center flex justify-center/i
    ]
  },
  'jQuery': {
    dom: [
      /jquery[-0-9.]*(\.min)?\.js/i,
      /jQuery\.fn\.init/i
    ]
  },


  'Laravel': {
    dom: [
      /Livewire/i
    ],
    cookies: [/laravel_session/i, /XSRF-TOKEN/i],
    files: ['/server.php', '/.env', '/composer.json']
  },
  'Django': {
    dom: [
      /name="csrfmiddlewaretoken"/i
    ],
    cookies: [/csrftoken/i, /sessionid/i], 
    files: ['/admin/login/', '/static/admin/css/base.css']
  },
  'Ruby on Rails': {
    dom: [
      /csrf-param" content="authenticity_token"/i,
      /data-turbolinks-track/i
    ],
    headers: { 'x-rack-cache': /.*/i, 'x-runtime': /.*/i, 'x-powered-by': /Phusion Passenger/i },
    cookies: [/_session_id/i]
  },
  'ASP.NET': {
    dom: [
      /__VIEWSTATE/i, 
      /__EVENTVALIDATION/i,
      /ctl00_/i
    ],
    headers: { 'x-aspnet-version': /.*/i, 'x-powered-by': /ASP\.NET/i, 'x-aspnetmvc-version': /.*/i },
    cookies: [/ASP\.NET_SessionId/i, /\.AspNetCore\.Antiforgery/i]
  },
  'Express.js': {
    headers: { 'x-powered-by': /^Express$/i }, 
    cookies: [/connect\.sid/i]
  },
  'Spring Boot (Java)': {
    headers: { 'x-application-context': /.*/i },
    cookies: [/JSESSIONID/i],
    files: ['/actuator/health', '/actuator/env', '/swagger-ui.html'] 
  },
  'PHP': {
    headers: { 'x-powered-by': /PHP/i },
    cookies: [/PHPSESSID/i],
    files: ['/phpinfo.php', '/index.php']
  },
  'Nginx': {
    headers: { 'server': /nginx/i }
  },
  'Apache': {
    headers: { 'server': /Apache/i }
  },
  'IIS': {
    headers: { 'server': /Microsoft-IIS/i }
  },


  'Cloudflare': {
    dom: [
      /cdn-cgi\/scripts/i,
      /cloudflare-static/i
    ],
    headers: { 'cf-ray': /.*/i, 'server': /cloudflare/i, 'cf-cache-status': /.*/i },
    cookies: [/__cfduid/i, /cf_clearance/i, /__cf_bm/i]
  },
  'AWS CloudFront': {
    headers: { 'x-amz-cf-id': /.*/i, 'x-amz-cf-pop': /.*/i, 'x-cache': /cloudfront/i }
  },
  'Akamai': {
    headers: { 'x-akamai-transformed': /.*/i, 'x-edgeconnect-midfetch': /.*/i }
  },
  'Fastly': {
    headers: { 'x-fastly-request-id': /.*/i, 'fastly-io-info': /.*/i, 'x-served-by': /cache-[a-z0-9]+-/i }
  },
  'F5 BIG-IP': {
    headers: { 'x-cprealm': /.*/i, 'server': /BigIP|F5/i },
    cookies: [/BIGipServer/i, /TS[0-9a-zA-Z]{6,8}/i]
  },


  'Google Analytics': {
    dom: [
      /GoogleAnalyticsObject/i, 
      /google-analytics\.com\/analytics\.js/i, 
      /gtag\(/i
    ],
    cookies: [/_ga/i, /_gid/i, /_gat/i]
  },
  'Google Tag Manager': {
    dom: [
      /googletagmanager\.com\/gtm\.js/i,
      /GTM-[A-Z0-9]+/i
    ]
  },
  'Facebook Pixel': {
    dom: [
      /connect\.facebook\.net\/en_US\/fbevents\.js/i,
      /fbq\('init'/i
    ],
    cookies: [/_fbp/i]
  },
  'Hotjar': {
    dom: [
      /static\.hotjar\.com\/c\/hotjar-/i,
      /hj\('hjSettings'/i
    ],
    cookies: [/_hjSession_/i, /_hjIncludedInSessionSample/i]
  }
};

const tstacksleep = (min = GLOBAL_MIN_SLEEP * 2, max = GLOBAL_MAX_SLEEP * 2) => {
  const ms = Math.floor(Math.random() * (max - min + 1) + min);
  return new Promise(resolve => setTimeout(resolve, ms));
};

/**
 * 
 * @param {number} min
 * @param {number} max
 */
const sleep = (min = GLOBAL_MIN_SLEEP, max = GLOBAL_MAX_SLEEP) => {
  const ms = Math.floor(Math.random() * (max - min + 1) + min);
  return new Promise(resolve => setTimeout(resolve, ms));
};
 async function checkPathExists(protocol, host, port, path) {
  return new Promise((resolve) => {
    const c_url = `${protocol === https ? 'https' : 'http'}://${host}:${port}${path}`;
    const options = { method: 'HEAD', timeout: 2000,
    agent: torAgent,
    headers: { 
        'User-Agent': getHumanHeaders(c_url),
        ...getWafEvasionHeaders()
      },
    rejectUnauthorized: false };
    const url = `${protocol === https ? 'https' : 'http'}://${host}:${port}${path}`;
    
    const req = protocol.request(url, options, (res) => {
      res.resume();
      resolve(res.statusCode === 200 || res.statusCode === 403); 
    });
    req.on('error', () => resolve(false));
    req.end();
  });
}

function calculateShannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  
  const charCounts = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    charCounts[char] = (charCounts[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = str.length;
  
  for (const char in charCounts) {
    const p = charCounts[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
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
      const info = parseDatabaseResponse(port, dataReceived);
      resolve({ port, open: true, banner: info });
    });

    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });

    socket.connect(port, host);
  });
}
function parseDatabaseResponse(port, buffer) {
  const raw = buffer.toString('utf8');
  let info = { software: 'Unknown DB', version: 'Unknown' };

  if (port === 5432) {
    info.software = 'PostgreSQL';

    const versionMatch = raw.match(/PostgreSQL ([\d.]+)/);
    if (versionMatch) info.version = versionMatch[1];
  } 
  else if (port === 27017) {
    info.software = 'MongoDB';
    const versionMatch = raw.match(/"version"\s*:\s*"([\d.]+)"/);
    if (versionMatch) info.version = versionMatch[1];
  }
  else if (port === 1433) {
    info.software = 'MSSQL';

    if (buffer.includes('Microsoft SQL Server')) info.version = 'Detected';
  }


  if (info.version === 'Unknown') {
    info.version = extractVersion(raw);
  }

  return info;
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
    if (port === 445) {
      return probeSMB(targetIp); 
    }
    if (DB_PROBES[port]) {
      return probeDatabase(port, targetIp);
    }
    return grabBanner(port, targetIp);
  });
  

  const udpPromises = COMMON_UDP_PORTS.map(port => probeUdpPort(port, targetIp));
  const [tcpResults, udpResults] = await Promise.all([
    Promise.all(tcpPromises),
    Promise.all(udpPromises)
  ]);
const openPorts = tcpResults.filter(r => r !== null && r.open);

  for (const r of openPorts.sort((a, b) => a.port - b.port)) {
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
  const openTcp = tcpResults.filter(r => r !== null && r.open);
  const openUdp = udpResults.filter(r => r !== null && r.open);


  if (openUdp.length > 0) {
    log(`\n  [#] Discovered ${openUdp.length} Open UDP Ports:`);
    openUdp.forEach(r => {
      log(`      [+] Port ${r.port}/UDP - Response: ${r.banner || 'No payload data returned'}`);
    });
  }


  if (openTcp.length === 0 && openUdp.length === 0) {
    log(`  [-] No standard infrastructure ports detected open.`);
    return;
  }
  const scanPromises = INFRA_PORTS.map(port => grabBanner(port, targetIp));
  const scanResults = await Promise.all(scanPromises);
  

  if (openPorts.length === 0) {
    log(`  [-] No standard infrastructure ports detected open.`);
    return;
  }

  for (const r of openPorts.sort((a, b) => a.port - b.port)) {
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
  }}}

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
    if (falsePositiveKeywords.some(keyword => context.includes(keyword))) {
      return false;
    }
  }

  return true;
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
    const req = https.get(`https://${hostname}`, { timeout: 5000, 
      agent: torAgent
    }, (res) => {
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
  
  const htmlBody = await fetchText(baseUrl);
  if (!htmlBody) {
    log(`          [-] Failed to retrieve base HTML for Shadow-Trust.`);
    return;
  }

  const $ = cheerio.load(htmlBody);
  const externalDomains = new Set();
  const rawReferences = [];

  $('script[src], link[href], img[src], iframe[src], form[action], a[href]').each((i, el) => {
    const urlAttr = $(el).attr('src') || $(el).attr('href') || $(el).attr('action');
    if (!urlAttr) return;

    if (urlAttr.startsWith('http') || urlAttr.startsWith('//')) {
      try {
        const fullUrl = urlAttr.startsWith('//') ? `https:${urlAttr}` : urlAttr;
        const urlObj = new URL(fullUrl);
        const hostname = urlObj.hostname.toLowerCase();
        

        if (!hostname.includes(host) && !WHITELIST_DOMAINS.some(wd => hostname.endsWith(wd))) {
          externalDomains.add(hostname);
          rawReferences.push({ source: fullUrl, tag: el.tagName });
        }
      } catch (e) {  }
    }
  });

  if (externalDomains.size === 0) {
      log(`          [-] No external dependencies found to analyze.`);
      return;
  }

  log(`          [*] Discovered ${externalDomains.size} unique external dependencies. Hunting for broken links...`);

  const tasks = Array.from(externalDomains).map(hostname => {
    return limit(async () => {

      await sleep(50, 150); 
      
      const isDead = await checkHostAvailability(hostname);
      
      if (isDead) {
        log(`          [!!!] CRITICAL SHADOW-TRUST ALERT: Abandoned Dependency Found!`);
        log(`                └─ Dead Host: ${hostname}`);
        const refs = rawReferences.filter(r => r.source.includes(hostname));
        refs.slice(0, 2).forEach(r => log(`                └─ Injected via: <${r.tag}> ${r.source}`));
      } 
      else {
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
               log(`          [!] TLD PERMUTATION RISK (Typo-Squatting possible)`);
               log(`              └─ Target relies on:  ${hostname}`);
               log(`              └─ Available for Reg: ${permutedHost}`);
             }
          }
        }
      }
    });
  });

  await Promise.all(tasks);
  log(`          [*] Shadow-Trust Analysis complete.`);
}
async function detectTechStack(host, port) {
  const isHttps = port === 443 || port === 8443;
  const protocol = isHttps ? https : http;
  
  return new Promise((resolve) => {
    const c_url = `${protocol === https ? 'https' : 'http'}://${host}:${port}/`;
    const options = {
      method: 'GET',
      timeout: 5000,
      rejectUnauthorized: false,
      agent: torAgent,
      headers: { 
'User-Agent': getHumanHeaders(c_url),
        ...getWafEvasionHeaders()
      }
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
          if (headerMatch || (sig.cookies && sig.cookies.some(re => cookies.some(c => re.test(c))))) {
            score++;
          }


          if (sig.files) {
            let fileFound = false;
            for (const path of sig.files) {

              await tstacksleep(300, 900); 
              
              const exists = await checkPathExists(protocol, host, port, path);
              if (exists) {
                fileFound = true;
                break; 
              }
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


const SECRET_PATTERNS = {
  'AWS Access Key': /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
  'Google API Key': /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  'Stripe Live Key': /\bsk_live_[0-9a-zA-Z]{24}\b/g,
  'Stripe Test Key': /\bsk_test_[0-9a-zA-Z]{24}\b/g,
  'Firebase URL': /\bhttps:\/\/[a-z0-9-]+\.firebaseio\.com\b/gi,
  'Internal IP': /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
  'Staging/Dev Domain': /\b(?:[a-zA-Z0-9-]+\.)*(?:staging|dev|test|uat|sandbox)\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/gi
};

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

function parseCommandLineArgs() {
  const args = process.argv.slice(2);

  for (let i = 0; i < args.length; i++) {
if (args[i] === '--guide' || args[i] === '--help' || args[i] === '-h') {
      displayGuide();
      process.exit(0);
    }
    if (args[i] === '--ports' && args[i + 1]) {
      const customPorts = args[i + 1]
        .split(',')
        .map(p => parseInt(p.trim(), 10))
        .filter(p => !isNaN(p));
        
      if (customPorts.length > 0) {
        COMMON_PORTS = customPorts;
        console.log(`[*] Loaded ${COMMON_PORTS.length} custom ports from command line.`);
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
      }}
    else if (args[i] === '--protate') {

      GLOBAL_ROTATE_ENABLED = true;
    }

    else if (args[i] === '--mode' && args[i + 1]) {
      const mode = args[i + 1].toLowerCase();
      if (['web', 'nonweb', 'both'].includes(mode)) {
        SCAN_MODE = mode;
        console.log(`[*] Target Scan Mode configured to: ${SCAN_MODE.toUpperCase()}`);
      } else {
        console.log(`[-] Invalid mode provided. Use 'web', 'infra', or 'both'. Defaulting to web.`);
      }
      i++;
    }

    else if (args[i] === '--tor') {
      const { enableTorProxy } = require('./tor-proxy');
      

      let proxyUrl = 'socks5h://127.0.0.1:9050'; 
      if (args[i + 1] && !args[i + 1].startsWith('--')) {
        proxyUrl = args[i + 1];
        i++; 
      }
      
      try {
        torAgent = enableTorProxy(proxyUrl);
        console.log(`[*] Tor proxy enabled via ${proxyUrl}`);
      } catch (err) {
        console.log(`[-] Failed to initialize Tor proxy: ${err.message}`);
      }
    }

    else if (args[i] === '--fuzzlist' && args[i + 1]) {
      const wordlistPath = args[i + 1];
      if (fs.existsSync(wordlistPath)) {
        try {
          const content = fs.readFileSync(wordlistPath, 'utf8');
          const customFuzz = content
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line.length > 0 && !line.startsWith('#')); 
            
          if (customFuzz.length > 0) {
            FUZZ_TARGETS = customFuzz;
            console.log(`[*] Loaded ${FUZZ_TARGETS.length} targets from custom wordlist: ${wordlistPath}`);
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
    GLOBAL_CONCURRENCY = value;
    console.log(`[*] Configured concurrency limit: ${GLOBAL_CONCURRENCY}`);
  } else {
    console.log(`[-] Invalid concurrency value. Using default (10).`);
  }
  i++; 
}

else if (args[i] === '--depth' && args[i + 1]) {
  const depth = parseInt(args[i + 1], 10);
  if (!isNaN(depth) && depth >= 0) {
    GLOBAL_FUZZ_DEPTH = depth;
    console.log(`[*] Configured fuzzing depth: ${GLOBAL_FUZZ_DEPTH}`);
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
          
          const processedSigs = processCustomSignatures(customSigs);
          

          TECH_SIGNATURES_PRO = { ...TECH_SIGNATURES_PRO, ...processedSigs };
          
          console.log(`[*] Loaded ${Object.keys(processedSigs).length} custom technology signatures from: ${sigPath}`);
        } catch (err) {
          console.log(`[-] Error reading or parsing signatures JSON: ${err.message}`);
        }
      } else {
        console.log(`[-] Signatures file not found: ${sigPath}. Using defaults.`);
      }
      i++; 
    }
    if (args[i] === '--sleep' && args[i + 1]) {
      const parts = args[i + 1].split(',').map(p => parseInt(p.trim(), 10));
      
      if (parts.length === 2 && !parts.some(isNaN)) {
        GLOBAL_MIN_SLEEP = parts[0];
        GLOBAL_MAX_SLEEP = parts[1];
        console.log(`[*] Configured global sleep range: ${GLOBAL_MIN_SLEEP}ms - ${GLOBAL_MAX_SLEEP}ms`);
      } else {
        console.log(`[-] Invalid sleep format. Use: --sleep min,max (e.g., --sleep 200,800)`);
      }
      i++;
    }
  }
}

async function detectWildcardDns(domain) {
  const randomSub = `sanity-check-${Math.random().toString(36).substring(2, 10)}.${domain}`;
  
  try {

    const ips = await dns.resolve4(randomSub);
    if (ips && ips.length > 0) {
      return ips[0]; 
    }
  } catch (err) {

  }
  return null;
}

function getSimilarity(str1, str2) {
  if (!str1 || !str2) return 0;
  if (str1 === str2) return 100;


  const words1 = new Set(str1.substring(0, 15000).split(/\s+/));
  const words2 = new Set(str2.substring(0, 15000).split(/\s+/));
  
  const intersection = new Set([...words1].filter(x => words2.has(x)));
  const union = new Set([...words1, ...words2]);
  
  return (intersection.size / union.size) * 100;
}

async function getDnsTxtIntel(domain) {
  log(`\n[*] Scanning DNS TXT Records for SaaS Fingerprints...`);
  try {
    const records = await dns.resolveTxt(domain);
    const flattened = records.flat();
    
    if (flattened.length === 0) {
      log(`  [-] No TXT records found.`);
      return;
    }

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

    flattened.forEach(rec => {
      let identified = false;
      for (const [provider, regex] of Object.entries(saasMarkers)) {
        if (regex.test(rec)) {
          log(`  [!] IDENTIFIED SaaS: ${provider}`);
          log(`      └─ Record: ${rec}`);
          identified = true;
        }
      }
      if (!identified) {
        log(`  [+] TXT Record: ${rec.substring(0, 80)}${rec.length > 80 ? '...' : ''}`);
      }
    });
  } catch (err) {
    log(`  [-] Could not resolve TXT records: ${err.message}`);
  }
}


async function attemptZoneTransfer(domain) {
  log(`\n[*] Checking for AXFR (Zone Transfer) Vulnerabilities...`);
  try {
    const nameServers = await dns.resolveNs(domain);
    log(`  [+] Found ${nameServers.length} Name Servers: ${nameServers.join(', ')}`);

    for (const ns of nameServers) {
      log(`  [*] Attempting AXFR on: ${ns}...`);
      

      const isTcpOpen = await new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(2000);
        socket.on('connect', () => { socket.destroy(); resolve(true); });
        socket.on('error', () => resolve(false));
        socket.on('timeout', () => { socket.destroy(); resolve(false); });
        socket.connect(53, ns);
      });

      if (!isTcpOpen) {
        log(`      [-] TCP Port 53 closed on ${ns}. AXFR unlikely.`);
        continue;
      }

      log(`      [!] TCP Port 53 OPEN. Potential for Zone Transfer.`);
      log(`          [Manual Check]: dig axfr @${ns} ${domain}`);
    }
  } catch (err) {
    log(`  [-] Could not resolve Name Servers for AXFR: ${err.message}`);
  }
}

async function fetchHackerTarget(domain) {
  try {
    const response = await fetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`);
    const text = await response.text();
    if (!text || text.includes("error") || text.includes("API count exceeded")) return [];
    
    return text.split('\n').map(line => line.split(',')[0]);
  } catch (err) {
    throw new Error('HackerTarget unreachable');
  }
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
  } catch (err) {
    throw new Error('Wayback Machine unreachable');
  }
}


async function getBaseline(host, port, basePath, protocol) {
  const probes = [];
  const probeCount = 3;

  log(`          [*] Establishing Triple-Probe Baseline for ${basePath}...`);

  for (let i = 0; i < probeCount; i++) {
    const randomStr = Math.random().toString(36).substring(2, 15);
    const randomPath = (basePath.endsWith('/') ? basePath : basePath + '/') + `probe_${randomStr}.html`;
    const url = `${protocol === https ? 'https' : 'http'}://${host}:${port}${randomPath}`;
    

    const body = await fetchText(url);
    probes.push({
      body: body || "",
      length: body ? body.length : 0
    });

    await sleep(100, 300); 
  }


  const len1 = probes[0].length;
  const len2 = probes[1].length;
  const len3 = probes[2].length;

  const isDynamic = (len1 !== len2) || (len2 !== len3);
  const avgLength = Math.floor((len1 + len2 + len3) / 3);
  

  const stability = getSimilarity(probes[0].body, probes[1].body);

  log(`          [+] Baseline established. Avg Length: ${avgLength} | Stability: ${stability.toFixed(2)}%`);
  if (isDynamic) log(`          [!] Warning: Dynamic content detected in 404 responses.`);

  return {
    isDynamic,
    avgLength,
    stability, 
    sampleBody: probes[0].body
  };
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
  } catch (err) {
    throw new Error('crt.sh unreachable or timed out');
  }
}

function fetchBuffer(targetUrl) {
  return new Promise((resolve) => {
    
    const protocol = targetUrl.startsWith('https') ? https : http;
    
    const options = {
      
      timeout: 10000,
      rejectUnauthorized: false,
      agent: torAgent,
      headers: { 
        'User-Agent': getHumanHeaders(targetUrl)["user-agent"],
        ...getWafEvasionHeaders()
      }
    };

    const req = protocol.get(targetUrl, options, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        return resolve(null);
      }
      
      const chunks = [];
      res.on('data', chunk => {
        chunks.push(chunk);

        if (Buffer.byteLength(Buffer.concat(chunks)) > 50e6) {
          resolve(body);
          res.destroy(); }
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}


async function downloadExposedFiles(files, host, port) {
  const safeHost = host.replace(/[^a-zA-Z0-9.-]/g, '_');
  const dir = `loot_${safeHost}_${port}`;
  

  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  console.log(`\n          [*] Downloading ${files.length} files to ./${dir}/ ...`);
  
  for (const file of files) {
    try {
      const fileContent = await fetchBuffer(file.url);
      if (fileContent) {

        const rawName = file.path.split('/').filter(Boolean).join('_') || 'unknown_file';
        const safeFileName = rawName.replace(/[^a-zA-Z0-9.-]/g, '_');
        const savePath = `${dir}/${safeFileName}`;
        
        fs.writeFileSync(savePath, fileContent);
        console.log(`              [+] Saved: ${savePath}`);
      } else {
        console.log(`              [-] Failed to download (or not 200 OK): ${file.url}`);
      }
    } catch (err) {
      console.log(`              [-] Error downloading ${file.url}: ${err.message}`);
    }
  }
  console.log(`          [*] Download phase complete.\n`);
}

function getWafEvasionHeaders() {
  const spoofedIps = ['127.0.0.1', 'localhost', '::1', '10.0.0.1', '192.168.1.1', '172.16.0.1'];
  const randomIp = spoofedIps[Math.floor(Math.random() * spoofedIps.length)];
  
  return {
    'X-Forwarded-For': randomIp,
    'X-Originating-IP': randomIp,
    'X-Remote-IP': randomIp,
    'X-Remote-Addr': randomIp,
    'X-Client-IP': randomIp,
    'X-Host': randomIp,
    'X-Real-IP': randomIp,
    'True-Client-IP': randomIp,
    'Forwarded': `for=${randomIp};proto=http;by=${randomIp}`,
    'Client-IP': randomIp,
    'X-Forwarded': randomIp,
    'X-Custom-IP-Authorization': randomIp
  };
}
function fetchText(targetUrl) {
  return new Promise((resolve) => {
    
    const protocol = targetUrl.startsWith('https') ? https : http;
    
    const options = {
      timeout: 5000,
      rejectUnauthorized: false,
      agent: torAgent,
      headers: { 
        'User-Agent': getHumanHeaders(targetUrl)["user-agent"],
        ...getWafEvasionHeaders()
      }
    };

    const req = protocol.get(targetUrl, options, (res) => {
      let body = '';
      res.on('data', chunk => {
        body += chunk;
        if (body.length > 5e6) { 
          resolve(body);
          res.destroy(); 
        } 
      });
      res.on('end', () => resolve(body));
    });
    req.on('error', () => resolve(''));
    req.on('timeout', () => { req.destroy(); resolve(''); });
  });
}

async function runWithLimit(items, taskFn, concurrency = 5) {
  const limit = pLimit(concurrency);

  const tasks = items.map((item) => {
    return limit(async () => {
        await sleep(150, 450); 
        return taskFn(item);
    });
  });

  return Promise.all(tasks);
}


 async function scrapeJsForSecrets(host, port) {
  const isHttps = port === 443 || port === 8443;
  const baseUrl = isHttps ? `https://${host}` : `http://${host}:${port}`;
  
  log(`\n      [*] Crawling client-side JS for secrets on Port ${port}...`);
  
  const htmlBody = await fetchText(baseUrl);
  if (!htmlBody) {
    log(`          [-] Failed to fetch HTML base page.`);
    return;
  }

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
      try {
        const absoluteUrl = new URL(jsPath, baseUrl).href;
        jsUrls.add(absoluteUrl);
      } catch (e) {

      }
    }
  });

  if (jsUrls.size === 0) {
    log(`          [-] No external JS files found in HTML.`);
    return;
  }

  log(`          [*] Found ${jsUrls.size} JS files. Scanning...`);
  let secretsFound = 0;

  for (const jsUrl of jsUrls) {
    const jsBody = await fetchText(jsUrl);
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
           } else {
           }
        }
      }
    }
  }

  if (secretsFound === 0) {
    log(`          [-] Scan complete: No secrets or internal data found.`);
  } else {
    log(`          [*] Scan complete: ${secretsFound} sensitive items identified.`);
  }
}

async function fuzzWeb(host, port, basePath = '/', currentDepth = 0, maxDepth = 2, visited = new Set(), exposedFiles = []) {
  if (currentDepth > maxDepth) return;

  const isHttps = port === 443 || port === 8443;
  const protocol = isHttps ? https : http;
  let foundCount = 0;

  if (!basePath.startsWith('/')) basePath = '/' + basePath;
  if (!basePath.endsWith('/')) basePath += '/';

  if (currentDepth === 0) {
    log(`\n      [*] Fuzzing Port ${port} with concurrency limit...`);
  }

  const baseline = await getBaseline(host, port, basePath, protocol);
  const isCatchAll = baseline && (baseline.status === 200 || baseline.status === 301 || baseline.status === 302);
  
  if (isCatchAll && currentDepth === 0) {
      log(`          [!] Wildcard/Catch-All routing detected. Applying advanced heuristics...`);
  }

  const directoriesToRecurse = [];

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
            method: method,
            hostname: host,
            port: port,
            path: fullPath,
            timeout: 2000,
            agent: torAgent,
            rejectUnauthorized: false,
            headers: { 
    'User-Agent': getHumanHeaders(c_url),
    ...getWafEvasionHeaders()
  }
          };

          const req = protocol.request(options, (res) => {
            res.resume(); 
            resolve({ 
              status: res.statusCode, 
              location: res.headers.location,
              headers: res.headers 
            });
          });

          req.on('error', () => resolve({ status: 0, headers: {} }));
          req.on('timeout', () => { req.destroy(); resolve({ status: 0, headers: {} }); });
          req.end();
        });
      };


      let responseData = await performProbe('HEAD');


      if (responseData.status === 405) {

        responseData = await performProbe('GET');
      }

      const { status, location, headers } = responseData;
      const contentLength = headers['content-length'];
      const contentType = headers['content-type'] || '';

      let isLegit = false;


if (status === 200) {
    const targetUrl = (isHttps ? 'https://' : 'http://') + host + ':' + port + fullPath;
    const currentBody = await fetchText(targetUrl);
    

    const similarityTo404 = getSimilarity(baseline.sampleBody, currentBody);


    if (similarityTo404 >= baseline.stability) {
        isLegit = false; 
    } else {
        isLegit = true;
    }
}

      if (isLegit) {
        log(`          [!] EXPOSED:   ${fullPath.padEnd(25)} (200 OK) [Length: ${contentLength || 'Unknown'}]`);
        foundCount++;
        

        if (!cleanTarget.endsWith('/')) {
            exposedFiles.push({ 
                url: (isHttps ? 'https://' : 'http://') + host + ':' + port + fullPath, 
                path: fullPath 
            });
        }
        
        if (cleanTarget.endsWith('/') || target.includes('.')) {
          if (cleanTarget.endsWith('/')) directoriesToRecurse.push(fullPath);
        }
      } 
      else if (status === 403) {
        log(`          [+] PROTECTED: ${fullPath.padEnd(25)} (403 Forbidden)`);
        foundCount++;
        if (cleanTarget.endsWith('/')) directoriesToRecurse.push(fullPath);
      }
      else if (status === 301 || status === 302) {
        if (isCatchAll && baseline.status === status && location === baseline.location) {

        } else if (location && (location.endsWith(fullPath + '/') || location.includes(fullPath + '/'))) {
          const dirPath = fullPath.endsWith('/') ? fullPath : fullPath + '/';
          log(`          [+] DIRECTORY: ${dirPath.padEnd(25)} (${status} Redirect)`);
          directoriesToRecurse.push(dirPath);
        }
      }
    });
  });

  await Promise.all(tasks);

  for (const dir of directoriesToRecurse) {
    log(`\n          [*] Recursing into directory: ${dir}`);

    await fuzzWeb(host, port, dir, currentDepth + 1, maxDepth, visited, exposedFiles);
  }


  if (currentDepth === 0) {
    if (foundCount === 0 && directoriesToRecurse.length === 0) {
      log(`          [-] Fuzzing complete: No exposed files found.`);
    } else if (exposedFiles.length > 0) {
      const downloadChoice = await promptYesNo(`\n          [?] Found ${exposedFiles.length} exposed files. Do you want to download them? (y/n): `);
      if (downloadChoice === 'y' || downloadChoice === 'yes') {
        await downloadExposedFiles(exposedFiles, host, port);
      } else {
        console.log(`          [*] Skipped downloading files.\n`);
      }
    }
  }
}

async function getMailIntel(domain) {
  const mailResults = { mx: [], spf: null, dmarc: false };
  
  try {
    const mx = await dns.resolveMx(domain).catch(() => []);
    if (mx.length > 0) {
      mailResults.mx = mx.sort((a, b) => a.priority - b.priority);
    }

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

function getTlsIntel(host, port) {
  return new Promise((resolve) => {
    const options = {
      host: host,
      port: port,
      servername: host,
      rejectUnauthorized: false,
      timeout: 5000
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate();
      socket.destroy();

      if (!cert || Object.keys(cert).length === 0) {
        return resolve({ success: false, error: 'No certificate found' });
      }

      resolve({
        success: true,
        issuer: cert.issuer.O || cert.issuer.CN || 'Unknown',
        validTo: cert.valid_to,
        san: cert.subjectaltname || 'None'
      });
    });

    socket.on('error', (err) => resolve({ success: false, error: err.message }));
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ success: false, error: 'Connection Timeout' });
    });
  });
}

const WAF_SIGNATURES = {
  'Cloudflare': { headers: ['cf-ray', 'server'], regex: /cloudflare/i },
  'Akamai': { headers: ['x-akamai-transformed', 'server'], regex: /akamai/i },
  'Sucuri': { headers: ['x-sucuri-id', 'x-sucuri-cache'], regex: /sucuri/i },
  'Imperva/Incapsula': { headers: ['x-iinfo', 'incap_ses', 'visid_incap'], regex: /incapsula|imperva/i },
  'ModSecurity': { headers: ['server'], regex: /mod_security|modsecurity/i },
  'AWS WAF': { headers: ['x-amzn-requestid', 'server'], regex: /awswaf/i },
  'F5 BIG-IP': { headers: ['x-cprealm', 'server'], regex: /big-ip|f5/i }
};

const TAKEOVER_FINGERPRINTS = [
  { provider: 'GitHub Pages', cname: 'github.io', signature: /There isn't a GitHub Pages site here/i },
  { provider: 'AWS S3', cname: 's3.amazonaws.com', signature: /The specified bucket does not exist/i },
  { provider: 'Heroku', cname: 'herokuapp.com', signature: /No such app/i },
  { provider: 'Zendesk', cname: 'zendesk.com', signature: /Help Center Closed|Oops, this help center no longer exists/i },
  { provider: 'Shopify', cname: 'myshopify.com', signature: /Sorry, this shop is currently unavailable/i },
  { provider: 'Tumblr', cname: 'domains.tumblr.com', signature: /Whatever you were looking for doesn't currently exist at this address/i },
  { provider: 'Pantheon', cname: 'pantheonsite.io', signature: /The edg-echo-1 server you are communicating with is configured/i }
];

async function queryWhoisServer(server, domain) {
  return new Promise((resolve, reject) => {
    const client = net.connect(43, server, () => {
      client.write(domain + '\r\n');
    });

    let data = '';
    client.setTimeout(5000);
    client.on('data', (chunk) => data += chunk);
    client.on('timeout', () => { client.destroy(); reject(new Error('Timeout')); });
    client.on('error', (err) => reject(err));
    client.on('end', () => resolve(data));
  });
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
  console.log("   Version 1.0 - Ready for sniffing...\n");
  console.log("================================================\n");
}



function parseWhoisText(text) {
  const intel = { org: 'N/A', creationDate: 'N/A', nameservers: [] };
  
  const orgMatch = text.match(/(?:Registrant Organization|org|Registrant):\s*(.*)/i);
  const dateMatch = text.match(/(?:Creation Date|created|Registration Date):\s*(.*)/i);
  const nsMatches = text.matchAll(/(?:Name Server|nserver):\s*([a-z0-9\.-]+)/gi);

  if (orgMatch) intel.org = orgMatch[1].trim();
  if (dateMatch) intel.creationDate = dateMatch[1].trim();
  for (const match of nsMatches) {
    intel.nameservers.push(match[1].toLowerCase());
  }

  return intel;
}

async function getLegacyWhois(domain) {
  try {
    const ianaResponse = await queryWhoisServer('whois.iana.org', domain);
    const referralMatch = ianaResponse.match(/whois:\s+([a-z0-9\.-]+)/i);
    
    let finalText = ianaResponse;
    
    if (referralMatch && referralMatch[1] && referralMatch[1] !== 'whois.iana.org') {
      finalText = await queryWhoisServer(referralMatch[1], domain);
    }

    return parseWhoisText(finalText);
  } catch (err) {
    return null;
  }
}

async function getWhoisIntel(domain) {
  log(`[*] Fetching WHOIS Intelligence for: ${domain}...`);
  
  try {
    const url = `https://www.rdap.net/domain/${domain}`;
    const response = await new Promise((resolve) => {
      https.get(url, { headers: { 'Accept': 'application/rdap+json' }, 
        agent: torAgent
      }, (res) => {
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

      log(`  [+] Organization: ${org}`);
      log(`  [+] Created On  : ${creationDate}`);
      log(`  [+] Nameservers : ${nameservers.join(', ')}`);
      log(`  [+] Source: RDAP (Success)`);
      return; 
    }
  } catch (e) {
  }

  log(`  [!] RDAP failed. Falling back to Legacy WHOIS (Port 43)...`);
  const legacyData = await getLegacyWhois(domain);
  
  if (legacyData) {
    log(`  [+] Organization: ${legacyData.org}`);
    log(`  [+] Created On  : ${legacyData.creationDate}`);
    log(`  [+] Nameservers : ${legacyData.nameservers.join(', ')}`);
    log(`  [+] Source: Legacy WHOIS`);
  } else {
    log(`  [-] All WHOIS methods failed.`);
  }
}

async function checkSubdomainTakeover(subdomain) {
  try {
    const cnames = await dns.resolveCname(subdomain).catch(() => []);
    if (cnames.length === 0) return null;

    for (const cname of cnames) {
      const targetProvider = TAKEOVER_FINGERPRINTS.find(fp => cname.includes(fp.cname));
      
      if (targetProvider) {
        const isVulnerable = await verifyTakeoverSignature(subdomain, targetProvider.signature);
        
        return {
          vulnerable: isVulnerable,
          provider: targetProvider.provider,
          cname: cname
        };
      }
    }
    return null;
  } catch (err) {
    return null;
  }
}

function verifyTakeoverSignature(host, signatureRegex) {
  return new Promise((resolve) => {
    const c_url = `${protocol === https ? 'https' : 'http'}://${host}:${port}${fullPath}`;
    const options = {
      method: 'GET',
      timeout: 5000,
      rejectUnauthorized: false,
      agent: torAgent,
      headers: { 
        'User-Agent': getHumanHeaders(c_url),
        ...getWafEvasionHeaders()
      }
    };

    const req = http.request(`http://${host}`, options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        resolve(signatureRegex.test(body));
      });
    });

    req.on('error', () => {
      const httpsReq = https.request(`https://${host}`, options, (res) => {
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

function promptYesNo(question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim().toLowerCase());
    });
  });
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

function checkSecurityHeaders(host, port) {
  return new Promise((resolve) => {
    
    const isHttps = port === 443 || port === 8443;
    const protocol = isHttps ? https : http;
    const c_url = `${protocol === https ? 'https' : 'http'}://${host}:${port}/`;
    const url = isHttps ? `https://${host}` : `http://${host}:${port}`;
    
    
    const options = {
      method: 'HEAD',
      timeout: 5000,
      rejectUnauthorized: false, 
      agent: torAgent,
    headers: { 
        'User-Agent': getHumanHeaders(c_url),
        ...getWafEvasionHeaders()
      }  
    };

    const req = protocol.request(url, options, (res) => {
      const headers = res.headers;
      const wafs = identifyWAF(headers);
      if (wafs) {
        log(`      [!] WAF DETECTED: ${wafs.join(', ')}`);
      }
      
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

const COMMON_SITEMAPS = [
  '/sitemap.xml', 
  '/sitemap_index.xml', 
  '/sitemaps.xml', 
  '/api/sitemap'
];

async function crawlSitemap(sitemapUrl, visitedSitemaps = new Set(), extractedUrls = new Set()) {
  if (visitedSitemaps.has(sitemapUrl) || visitedSitemaps.size > 15) return extractedUrls;
  visitedSitemaps.add(sitemapUrl);

  const body = await fetchText(sitemapUrl);
  if (!body) return extractedUrls;

  if (body.includes('<sitemapindex')) {
    const subSitemaps = [...body.matchAll(/<loc>(.*?)<\/loc>/g)].map(m => m[1]);
    log(`              -> [Index] Found ${subSitemaps.length} nested sitemaps. Following...`);
    
    for (const sub of subSitemaps.slice(0, 5)) {
      await crawlSitemap(sub, visitedSitemaps, extractedUrls);
    }
    if (subSitemaps.length > 5) log(`              -> Notice: Skipped ${subSitemaps.length - 5} nested sitemaps to save time.`);
  } 
  else if (body.includes('<urlset')) {
    const urls = [...body.matchAll(/<loc>(.*?)<\/loc>/g)].map(m => m[1]);
    urls.forEach(u => extractedUrls.add(u));
  }

  return extractedUrls;
}

async function advancedDiscoveryScan(host, port) {
  const isHttps = port === 443 || port === 8443;
  const baseUrl = isHttps ? `https://${host}` : `http://${host}:${port}`;
  
  log(`\n      [*] Executing Advanced Discovery (Robots/Sitemaps) on Port ${port}...`);

  let discoveredSitemaps = [];
  const sensitivePaths = new Set();

  const robotsBody = await fetchText(`${baseUrl}/robots.txt`);
  
  if (robotsBody && robotsBody.length > 5) {
    log(`          [+] robots.txt FOUND! (${robotsBody.length} bytes)`);

    const lines = robotsBody.split(/\r?\n/);
    const disallows = [];
    const sitemaps = [];

    for (let line of lines) {
      line = line.trim();
      if (line.toLowerCase().startsWith('disallow:')) {
        const path = line.split(':')[1]?.trim();
        if (path && path !== '/') disallows.push(path);
      }
      if (line.toLowerCase().startsWith('sitemap:')) {
        const url = line.split(/sitemap:/i)[1]?.trim();
        if (url) sitemaps.push(url);
      }
    }

    if (disallows.length > 0) {
      log(`              -> Found ${disallows.length} 'Disallow' rules.`);
      disallows.forEach(p => sensitivePaths.add(p));
    }

    if (sitemaps.length > 0) {
      discoveredSitemaps.push(...sitemaps);
      log(`              -> Discovered ${sitemaps.length} Sitemap(s) via robots.txt.`);
    }


    const saveChoice = await promptYesNo(`\n          [?] Do you want to save this robots.txt to a file? (y/n): `);
    
    if (saveChoice === 'y' || saveChoice === 'yes') {
      const safeHost = host.replace(/[^a-zA-Z0-9.-]/g, '_');
      const filename = `${safeHost}_${port}_robots.txt`;
      
      try {
        fs.writeFileSync(filename, robotsBody);
        console.log(`          [+] SUCCESS: Saved raw contents to ./${filename}\n`);
      } catch (err) {
        console.log(`          [-] ERROR: Failed to save file (${err.message})\n`);
      }
    } else {
      console.log(`          [*] Skipped saving file.\n`);
    }

  } else {
    log(`          [-] No robots.txt discovered or file is empty.`);
  }

  if (discoveredSitemaps.length === 0) {
    for (const path of COMMON_SITEMAPS) {
      const target = `${baseUrl}${path}`;
      const exists = await new Promise((resolve) => {
        const protocol = isHttps ? https : http;
        protocol.request(target, { method: 'HEAD', timeout: 2000, rejectUnauthorized: false, 
          agent: torAgent
        }, (res) => {
          resolve(res.statusCode === 200);
          res.resume();
        }).on('error', () => resolve(false)).end();
      });

      if (exists) {
        discoveredSitemaps.push(target);
        log(`              -> Guessed Sitemap location: ${path}`);
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
      
      const interestingKeywords = ['admin', 'login', 'api', 'dashboard', 'user', 'config', 'dev'];
      const juicyUrls = Array.from(allExtractedUrls).filter(url => 
        interestingKeywords.some(keyword => url.toLowerCase().includes(keyword))
      );

      if (juicyUrls.length > 0) {
        log(`              -> Found ${juicyUrls.length} potentially sensitive URLs in sitemap:`);
        juicyUrls.slice(0, 3).forEach(url => log(`                 └─ ${url}`));
        if (juicyUrls.length > 3) log(`                 └─ ...and more`);
      }
    } else {
      log(`          [-] Sitemaps were empty or unreadable.`);
    }
  } else {
    log(`          [-] No sitemaps found.`);
  }

  return Array.from(sensitivePaths);
}

function getJson(url) {
  return new Promise((resolve, reject) => {
  
    const options = {
    agent: torAgent,
      headers: { 
        'User-Agent': getHumanHeaders(url)["user-agent"],
        ...getWafEvasionHeaders()
      },
      timeout: 5000
    };

    https.get(url, options, (res) => {
      let data = '';
      if (res.statusCode !== 200) return reject(new Error(`Status: ${res.statusCode}`));
      
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Invalid JSON response'));
        }
      });
    }).on('error', reject);
  });
}

function extractVersion(str) {
  const match = str.match(/(\d+\.\d+(\.\d+)?(-[a-zA-Z0-9.]+)?)/);
  return match ? match[0] : 'Unknown';
}

function isPrivateIp(ip) {
  return /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)/.test(ip);
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

async function resolveMinecraftSrv(domain) {
  try {
    const records = await dns.resolveSrv(`_minecraft._tcp.${domain}`);
    if (records && records.length > 0) {
      return { host: records[0].name, port: records[0].port };
    }
  } catch (e) {
    return null; 
  }
}

async function smartResolve(domain) {
  let results = { ip: null, port: null, method: null };

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
    if (ips.length > 0) return { ip: ips[0], port: 25565, method: 'A Record' };
  } catch (e) { }

  try {
    const lookup = await dns.lookup(domain);
    if (lookup.address) return { ip: lookup.address, port: 25565, method: 'System Lookup' };
  } catch (e) { }

  return null;
}

async function lookupCVEs(software, version) {
  if (!software || software === 'Unknown' || software === 'Web Server' || !version || version === 'Unknown') {
    return null;
  }

  const query = encodeURIComponent(`${software} ${version}`);
  const apiUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${query}&resultsPerPage=3`;

  try {
    const data = await getJson(apiUrl);
    
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

async function getPassiveSubdomains(domain) {
  log(`\n[*] Querying Passive Sources Concurrently (HackerTarget, Wayback, crt.sh)...`);
  const subdomains = new Set();

  const tasks = [
    fetchHackerTarget(domain),
    fetchWayback(domain),
    fetchCrtSh(domain)
  ];

  const results = await Promise.allSettled(tasks);

  results.forEach((result, index) => {
    if (result.status === 'fulfilled' && result.value) {
      result.value.forEach(sub => subdomains.add(sub.toLowerCase().trim()));
    } else if (result.status === 'rejected') {
      log(`  [!] Source ${index + 1} failed: ${result.reason.message}`);
    }
  });

  const finalResult = Array.from(subdomains);
  finalResult.forEach(s => log(`  [+] Found: ${s}`));
  
  if (finalResult.length === 0) {
    log(`  [-] No subdomains found in passive sources.`);
  }
  return finalResult;
}


async function bruteSubdomainsFromFile(domain, wildcardIp = null) {
  const path = 'subdomains.txt';
  if (!fs.existsSync(path)) {
    log(`  [-] Skipping brute-force ('${path}' not found).`);
    return [];
  }
  
  const words = fs.readFileSync(path, 'utf8').split('\n').map(w => w.trim()).filter(w => w && !w.startsWith('#'));
  log(`\n[*] Brute-forcing ${words.length} potential subdomains...`);
  
  const found = [];
  for (let i = 0; i < words.length; i += 20) {
    const chunk = words.slice(i, i + 20);
    const results = await Promise.all(chunk.map(sub => 
      dns.resolve4(`${sub}.${domain}`).then(ip => ({ sub: `${sub}.${domain}`, ip: ip[0] })).catch(() => null)
    ));

    results.forEach(r => { 
      if (r) { 

        if (wildcardIp && r.ip === wildcardIp) {
            
            return;
        }

        log(`  [+] Active: ${r.sub} (${r.ip})`); 
        found.push(r.sub); 
      } 
    });
  }
  return found;
}


async function fetchIntel(input) {
  sessionReport = ""; 
  log(`\n========================================`);
  log(`[*] TARGET: ${input}`);
  log(`========================================`);
  
  const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(input);
  const isDomain = !isIp;
  
  if (GLOBAL_ROTATE_ENABLED) {
    await refreshProxyList();
    rotateProxy();
  }
  
  if (isDomain) {
    log(`\n--- [ WHOIS ENRICHMENT ] ---`);
    await getWhoisIntel(input);
    
    log(`\n--- [ DNS INTELLIGENCE ] ---`);
    const wildcardIp = await detectWildcardDns(input);
  if (wildcardIp) {
    log(`  [!] WARNING: Wildcard DNS detected! (${wildcardIp})`);
    log(`      Subdomains resolving to this IP will be ignored to ensure 100% precision.`);
  } else {
    log(`  [+] No Wildcard DNS detected. Precision mode: High.`);
  }
    await getDnsTxtIntel(input);
    await attemptZoneTransfer(input);
  }
  
  try {
    let targetIp = input;
    let targetPorts = [...COMMON_PORTS];

    if (!isIp) {
      log(`[*] Resolving domain...`);
      const resolution = await smartResolve(input);

      if (resolution) {
        targetIp = resolution.ip;
        log(`  [+] Resolved via ${resolution.method}: ${targetIp}`);
        
        if (resolution.port && !targetPorts.includes(resolution.port)) {
          log(`  [+] Custom Port detected: ${resolution.port}`);
          targetPorts.push(resolution.port);
        }
      
        const discoveredSubdomains = await getPassiveSubdomains(input);
        if (discoveredSubdomains.length > 0) {
          log(`\n[*] Checking ${discoveredSubdomains.length} subdomains for takeover vulnerabilities...`);
          let takeoverFound = false;

          for (const sub of discoveredSubdomains) {
            const takeoverResult = await checkSubdomainTakeover(sub);
            
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
          if (!takeoverFound) {
            log(`  [-] No vulnerable CNAME configurations detected.`);
          }
        }
        log(`\n[*] Checking Mail Configuration...`);
        const mailInfo = await getMailIntel(input);
        
        if (mailInfo && mailInfo.mx.length > 0) {
          log(`  [+] MX Records:`);
          mailInfo.mx.forEach(m => log(`      - ${m.exchange} (Priority: ${m.priority})`));
          
          if (mailInfo.spf) log(`  [+] SPF Record: ${mailInfo.spf.substring(0, 50)}...`);
          if (mailInfo.dmarc) log(`  [+] DMARC: Configured`);
        } else {
          log(`  [-] No MX records found.`);
        }
      }
      else {
        log(`  [!] Could not resolve "${input}" to an IPv4 address.`);
        log(`  [!] Try checking if the domain is typed correctly.`);
        return ask();
      }
    }
   
    log(`\n[*] Fetching Geo/ISP...`);
    try {
      const intel = await getJson(`https://ipwho.is/${targetIp}`);
      if (intel.success) {
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
      log(`  [!] API Connection Error.`);
    }

    log(`\n[*] Scanning ${targetPorts.length} Ports...`);
    
    const scanPromises = targetPorts.map(port => grabBanner(port, targetIp));
    const scanResults = await Promise.all(scanPromises);
    
    const openPorts = scanResults.filter(r => r !== null && r.open);

    log(`\n[*] Running Heuristic Analysis...`);
    const honeypotIssues = analyzeForHoneypot(openPorts);
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
        
        const cves = await lookupCVEs(software, version);
        
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

      if (webPorts.includes(443)) {
        webPorts = webPorts.filter(p => p !== 80);
      }
      if (webPorts.includes(8443)) {
        webPorts = webPorts.filter(p => p !== 8080);
      }
      
      if (webPorts.length > 0) {
        log(`\n[*] Analyzing HTTP Security Headers...`);
        for (const webPort of webPorts) {
          const headerIntel = await checkSecurityHeaders(input, webPort);
          
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
            const sslIntel = await getTlsIntel(input, webPort);

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
          const techIntel = await detectTechStack(input, webPort);
          
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
          const restrictedPaths = await advancedDiscoveryScan(input, webPort);
          await fuzzWeb(input, webPort, '/', 0, GLOBAL_FUZZ_DEPTH);
          await scrapeJsForSecrets(input, webPort);
          await analyzeShadowTrust(input, webPort);
          const isHttps = webPort === 443 || webPort === 8443;
          const scheme = isHttps ? 'https' : 'http';
          const constructedUrl = `${scheme}://${input}:${webPort}`;
          
          if (GLOBAL_BREADCRUMB_ENABLED) {
            if (GLOBAL_BREADCRUMB_ENABLED) {
  await breadcrumbScan(constructedUrl, GLOBAL_BREADCRUMB_HOPS);
} else {
  log(`      [*] Breadcrumb Crawling is disabled. Use --breadcrumb to enable.`);
}
          } else {
            log(`      [*] Breadcrumb Crawling is disabled. Use --breadcrumb to enable.`);
          }
        }
      }
      }
      if (SCAN_MODE === 'infra' || SCAN_MODE === 'both') {
         await scanInfrastructure(targetIp);
      }
    } else {
      log(`  [-] No open ports detected.`);
    }

  } catch (err) {
    log(`\n[!] Fatal Error: ${err.message}`);
  }
  
  log(`========================================\n`);

  
  const wantToSave = await promptYesNo(`[?] Scan complete. Download full report to .txt? (y/n): `);

  if (wantToSave === 'y' || wantToSave === 'yes') {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const safeHost = input.replace(/[^a-z0-9]/gi, '_');
    const filename = `recon_${safeHost}_${timestamp}.txt`;

    try {
      fs.writeFileSync(filename, sessionReport);
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
      displayGuide(); // Calls your existing L257 function
      return ask();   // Prompt again so they can enter a target
    }


    if (input) {
      fetchIntel(input);
    } else {
      ask(); // Loop if input is empty
    }
  });
}

console.clear();
parseCommandLineArgs();
limit = pLimit(GLOBAL_CONCURRENCY);
displayBanner();
ask();