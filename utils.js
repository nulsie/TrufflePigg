const { URL } = require('node:url');
const http = require('node:http');
const https = require('node:https');


let GLOBAL_MIN_SLEEP = 100;
let GLOBAL_MAX_SLEEP = 500;
let sessionReport = "";

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


function log(...args) {
  const message = args.join(' ');
  console.log(message);
  sessionReport += message + "\n";
}

function getSessionReport() {
  return sessionReport;
}

function clearSessionReport() {
  sessionReport = "";
}


function setSleepConfig(min, max) {
  GLOBAL_MIN_SLEEP = min;
  GLOBAL_MAX_SLEEP = max;
}

const tstacksleep = (min = GLOBAL_MIN_SLEEP * 2, max = GLOBAL_MAX_SLEEP * 2) => {
  const ms = Math.floor(Math.random() * (max - min + 1) + min);
  return new Promise(resolve => setTimeout(resolve, ms));
};

const sleep = (min = GLOBAL_MIN_SLEEP, max = GLOBAL_MAX_SLEEP) => {
  const ms = Math.floor(Math.random() * (max - min + 1) + min);
  return new Promise(resolve => setTimeout(resolve, ms));
};


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

function getSimilarity(str1, str2) {
  if (!str1 || !str2) return 0;
  if (str1 === str2) return 100;

  const words1 = new Set(str1.substring(0, 15000).split(/\s+/));
  const words2 = new Set(str2.substring(0, 15000).split(/\s+/));
  
  const intersection = new Set([...words1].filter(x => words2.has(x)));
  const union = new Set([...words1, ...words2]);
  
  return (intersection.size / union.size) * 100;
}

function extractVersion(str) {
  const match = str.match(/(\d+\.\d+(\.\d+)?(-[a-zA-Z0-9.]+)?)/);
  return match ? match[0] : 'Unknown';
}

function isPrivateIp(ip) {
  return /^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|169\.254\.)/.test(ip);
}


function getHumanHeaders(targetUrl) {
  const profile = BROWSER_PROFILES[Math.floor(Math.random() * BROWSER_PROFILES.length)];
  
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


function fetchText(targetUrl, agent = null) {
  return new Promise((resolve) => {
    const protocol = targetUrl.startsWith('https') ? https : http;
    
    const options = {
      timeout: 5000,
      rejectUnauthorized: false,
      agent: agent,
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

function fetchBuffer(targetUrl, agent = null) {
  return new Promise((resolve) => {
    const protocol = targetUrl.startsWith('https') ? https : http;
    
    const options = {
      timeout: 10000,
      rejectUnauthorized: false,
      agent: agent,
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
          resolve(Buffer.concat(chunks));
          res.destroy(); 
        }
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
    });
    
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}

function getJson(url, agent = null) {
  return new Promise((resolve, reject) => {
    const options = {
      agent: agent,
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


function promptYesNo(rl, question) {
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      resolve(answer.trim().toLowerCase());
    });
  });
}

module.exports = {
  log,
  getSessionReport,
  clearSessionReport,
  setSleepConfig,
  tstacksleep,
  sleep,
  calculateShannonEntropy,
  getSimilarity,
  extractVersion,
  isPrivateIp,
  getHumanHeaders,
  getWafEvasionHeaders,
  stealthWrite,
  fetchText,
  fetchBuffer,
  getJson,
  promptYesNo
};