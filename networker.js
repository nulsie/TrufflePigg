#!/usr/bin/env node
const https = require('node:https');
const http = require('node:http');
const http2 = require('node:http2');
const { URL } = require('node:url');
const { SocksClient } = require('socks');
const fs = require('node:fs');

 const {
  HTTP2_HEADER_PATH,
  HTTP2_HEADER_METHOD,
  HTTP2_HEADER_AUTHORITY,
  HTTP2_HEADER_SCHEME,
  HTTP2_HEADER_USER_AGENT,
} = http2.constants;

const BROWSER_PROFILES = [
  {
    ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ch: {
      "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Windows"',
    }
  },
  {
    ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    ch: {
      "sec-ch-ua": '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"macOS"',
    }
  },
  {
    ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ch: {
      "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
      "sec-ch-ua-mobile": "?0",
      "sec-ch-ua-platform": '"Linux"',
    }
  }
];


let PROXY_LIST = [];
let CURRENT_PROXY_INFO = null;
let GLOBAL_ROTATE_ENABLED = false;


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

async function refreshProxyList(source = 'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt') {
  return new Promise((resolve) => {
    const getter = source.startsWith('http') ? https : fs;
    
    if (source.startsWith('http')) {
      https.get(source, (res) => {
        let data = '';
        res.on('data', d => data += d);
        res.on('end', () => {
          PROXY_LIST = data.split(/\r?\n/).filter(line => line.includes(':'));
          resolve(PROXY_LIST.length);
        });
      }).on('error', () => resolve(0));
    } else {
      try {
        const data = fs.readFileSync(source, 'utf8');
        PROXY_LIST = data.split(/\r?\n/).filter(line => line.includes(':'));
        resolve(PROXY_LIST.length);
      } catch (e) {
        resolve(0);
      }
    }
  });
}

/**
 * Rotates to a new proxy from the list
 */
function rotateProxy() {
  if (PROXY_LIST.length === 0) return null;
  const randomIndex = Math.floor(Math.random() * PROXY_LIST.length);
  const [host, port] = PROXY_LIST[randomIndex].split(':');
  CURRENT_PROXY_INFO = { host, port: parseInt(port) };
  return CURRENT_PROXY_INFO;
}

/**
 * Main Fetching Engine with Proxy and HTTP/2 support
 */
async function stealthFetch(targetUrl, options = {}) {
  const parsed = new URL(targetUrl);
  const profile = BROWSER_PROFILES[Math.floor(Math.random() * BROWSER_PROFILES.length)];
  
  const headers = {
    'User-Agent': profile.ua,
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    ...profile.ch,
    ...options.headers
  };

  
  if (CURRENT_PROXY_INFO || options.useTor) {
    const proxyOptions = options.useTor 
      ? { host: '127.0.0.1', port: 9050 } 
      : CURRENT_PROXY_INFO;

    const info = await SocksClient.createConnection({
      proxy: {
        host: proxyOptions.host,
        port: proxyOptions.port,
        type: 5
      },
      command: 'connect',
      destination: {
        host: parsed.hostname,
        port: parsed.port ? parseInt(parsed.port) : 443
      }
    });

    
    return new Promise((resolve, reject) => {
      const req = https.request({
        method: options.method || 'GET',
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        createConnection: () => info.socket,
        headers: headers
      }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve({ body, statusCode: res.statusCode, headers: res.headers }));
      });
      req.on('error', reject);
      req.end();
    });
  }

  
  return new Promise((resolve, reject) => {
    const req = https.request(targetUrl, {
      method: options.method || 'GET',
      headers: headers
    }, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve({ body, statusCode: res.statusCode, headers: res.headers }));
    });
    req.on('error', reject);
    req.end();
  });
}

 async function stealthFetchH2(targetUrl, options = {}) {
  return new Promise(async (resolve, reject) => {
    const url = new URL(targetUrl);
    let socket;
    
    const profile = BROWSER_PROFILES[Math.floor(Math.random() * BROWSER_PROFILES.length)];

    try {
      
      if (CURRENT_PROXY_INFO || options.useTor) {
        const proxy = options.useTor ? { host: '127.0.0.1', port: 9050 } : CURRENT_PROXY_INFO;
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
        [HTTP2_HEADER_METHOD]: options.method || 'GET',
        [HTTP2_HEADER_PATH]: url.pathname + url.search,
        [HTTP2_HEADER_SCHEME]: url.protocol.replace(':', ''),
        [HTTP2_HEADER_AUTHORITY]: url.hostname,
        [HTTP2_HEADER_USER_AGENT]: profile.ua,
        ...getWafEvasionHeaders(), 
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'accept-language': 'en-US,en;q=0.5',
        ...options.headers
      });

      let data = '';
      req.setEncoding('utf8');
      req.on('data', (chunk) => { data += chunk; });
      req.on('end', () => {
        client.close();
        resolve({ body: data, statusCode: 200, headers: {} }); 
      });
      
      req.end();

    } catch (err) {
      reject(err);
    }
  });
}

module.exports = {
  BROWSER_PROFILES,
  refreshProxyList,
  rotateProxy,
  stealthFetch,
  stealthFetchH2,
  setRotateEnabled: (val) => { GLOBAL_ROTATE_ENABLED = val; },
  getCurrentProxy: () => CURRENT_PROXY_INFO
};