
const { SocksProxyAgent } = require('socks-proxy-agent');
const http = require('node:http');
const https = require('node:https');

/**
 * 
 * @param {string} proxyUrl 
 */
function enableTorProxy(proxyUrl = 'socks5h://127.0.0.1:9050') {
    console.log(`\n[*] Initializing Tor Proxy routing via ${proxyUrl}...`);
    

    const agent = new SocksProxyAgent(proxyUrl);


    http.globalAgent = agent;
    https.globalAgent = agent;


    process.env.http_proxy = proxyUrl;
    process.env.https_proxy = proxyUrl;
    process.env.ALL_PROXY = proxyUrl;

    console.log(`[+] Global HTTP/HTTPS traffic is now wrapped and routed through Tor.`);
    
    return agent;
}

module.exports = { enableTorProxy };