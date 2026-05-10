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

const COMMON_PORTS = [
  21, 22, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 6379, 8080, 8888, 25565
];

const FUZZ_TARGETS = [
  '.env', '.git/config', '.htaccess', 'phpinfo.php', 'config.php', 
  'wp-config.php', 'backup.zip', 'login.php', 'docker-compose.yml', 
  'server-status', '.ssh/id_rsa', '.aws/credentials', 'composer.json',
  'admin/', 'api/', 'api/v1/', 'wp-json/wp/v2/users/', 'backup/', 'config/', 'dev/'
];

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

const TECH_SIGNATURES_PRO = {
  'WordPress': {
    dom: [/wp-content\/themes/i, /wp-includes\/js/i, /<meta name="generator" content="WordPress/i, /<link rel="https:\/\/api\.w\.org\/"/i],
    headers: { 'link': /<[^>]+rest_route=\/>/i },
    cookies: [/wp-settings-[0-9]+/i, /wordpress_logged_in_/i, /wordpress_test_cookie/i],
    files: ['/wp-login.php', '/wp-admin/admin-ajax.php', '/xmlrpc.php', '/license.txt', '/readme.html']
  },
  'Drupal': {
    dom: [/Drupal\.settings/i, /sites\/default\/files/i, /<meta name="Generator" content="Drupal/i, /data-drupal-link-system-path/i],
    headers: { 'x-generator': /Drupal/i, 'x-drupal-cache': /.*/i, 'x-drupal-dynamic-cache': /.*/i },
    files: ['/core/install.php', '/CHANGELOG.txt', '/user/login']
  },
  'Joomla': {
    dom: [/<meta name="generator" content="Joomla!/i, /Joomla\.options/i, /components\/com_/i],
    headers: { 'x-content-encoded-by': /Joomla/i },
    cookies: [/joomla_user_state/i, /[a-f0-9]{32}/i],
    files: ['/administrator/index.php', '/language/en-GB/en-GB.xml', '/README.txt']
  },
  'Magento': {
    dom: [/mage\/cookies/i, /text\/x-magento-init/i, /skin\/frontend\//i],
    headers: { 'x-magento-cache-id': /.*/i, 'x-magento-tags': /.*/i },
    cookies: [/frontend/i, /store/i, /adminhtml/i],
    files: ['/magento_version', '/pub/static/deployed_version.txt', '/app/etc/env.php']
  },
  'Shopify': {
    dom: [/cdn\.shopify\.com/i, /Shopify\.theme/i, /window\.ShopifyAnalytics/i],
    headers: { 'x-shopid': /.*/i, 'x-shardid': /.*/i },
    cookies: [/_secure_session_id/i, /_shopify_s/i, /_shopify_y/i]
  },
  'Ghost': {
    dom: [/<meta name="generator" content="Ghost/i, /ghost-sdk\.min\.js/i],
    headers: { 'x-ghost-cache-status': /.*/i },
    files: ['/ghost/api/v3/content/', '/ghost/']
  },
  'Next.js': {
    dom: [/__NEXT_DATA__/i, /<script[^>]+src="[^"]*\/_next\//i, /next-head-count/i],
    headers: { 'x-powered-by': /Next\.js/i },
    files: ['/_next/static/chunks/main.js', '/_next/static/css/']
  },
  'React': { dom: [/data-reactroot/i, /__REACT_DEVTOOLS_GLOBAL_HOOK__/i, /<div id="root">/i] },
  'Vue.js': { dom: [/data-v-[a-z0-9]{8}/i, /__VUE__/i, /vue-app/i] },
  'Nuxt.js': { dom: [/__NUXT__/i, /_nuxt\//i], headers: { 'x-nuxt-version': /.*/i } },
  'Angular': { dom: [/ng-app/i, /ng-version/i, /_ngcontent-/i, /ng-reflect-/i] },
  'Svelte': { dom: [/__svelte-meta/i, /svelte-[a-z0-9]{6}/i] },
  'Bootstrap': { dom: [/bootstrap(\.bundle)?(\.min)?\.js/i, /bootstrap(\.min)?\.css/i, /class="[^"]*col-md-[0-9]/i] },
  'Tailwind CSS': { dom: [/tailwind/i, /class="[^"]*text-center flex justify-center/i] },
  'jQuery': { dom: [/jquery[-0-9.]*(\.min)?\.js/i, /jQuery\.fn\.init/i] },
  'Laravel': { dom: [/Livewire/i], cookies: [/laravel_session/i, /XSRF-TOKEN/i], files: ['/server.php', '/.env', '/composer.json'] },
  'Django': { dom: [/name="csrfmiddlewaretoken"/i], cookies: [/csrftoken/i, /sessionid/i], files: ['/admin/login/', '/static/admin/css/base.css'] },
  'Ruby on Rails': {
    dom: [/csrf-param" content="authenticity_token"/i, /data-turbolinks-track/i],
    headers: { 'x-rack-cache': /.*/i, 'x-runtime': /.*/i, 'x-powered-by': /Phusion Passenger/i },
    cookies: [/_session_id/i]
  },
  'ASP.NET': {
    dom: [/__VIEWSTATE/i, /__EVENTVALIDATION/i, /ctl00_/i],
    headers: { 'x-aspnet-version': /.*/i, 'x-powered-by': /ASP\.NET/i, 'x-aspnetmvc-version': /.*/i },
    cookies: [/ASP\.NET_SessionId/i, /\.AspNetCore\.Antiforgery/i]
  },
  'Express.js': { headers: { 'x-powered-by': /^Express$/i }, cookies: [/connect\.sid/i] },
  'Spring Boot (Java)': { headers: { 'x-application-context': /.*/i }, cookies: [/JSESSIONID/i], files: ['/actuator/health', '/actuator/env', '/swagger-ui.html'] },
  'PHP': { headers: { 'x-powered-by': /PHP/i }, cookies: [/PHPSESSID/i], files: ['/phpinfo.php', '/index.php'] },
  'Nginx': { headers: { 'server': /nginx/i } },
  'Apache': { headers: { 'server': /Apache/i } },
  'IIS': { headers: { 'server': /Microsoft-IIS/i } },
  'Cloudflare': {
    dom: [/cdn-cgi\/scripts/i, /cloudflare-static/i],
    headers: { 'cf-ray': /.*/i, 'server': /cloudflare/i, 'cf-cache-status': /.*/i },
    cookies: [/__cfduid/i, /cf_clearance/i, /__cf_bm/i]
  },
  'AWS CloudFront': { headers: { 'x-amz-cf-id': /.*/i, 'x-amz-cf-pop': /.*/i, 'x-cache': /cloudfront/i } },
  'Akamai': { headers: { 'x-akamai-transformed': /.*/i, 'x-edgeconnect-midfetch': /.*/i } },
  'Fastly': { headers: { 'x-fastly-request-id': /.*/i, 'fastly-io-info': /.*/i, 'x-served-by': /cache-[a-z0-9]+-/i } },
  'F5 BIG-IP': { headers: { 'x-cprealm': /.*/i, 'server': /BigIP|F5/i }, cookies: [/BIGipServer/i, /TS[0-9a-zA-Z]{6,8}/i] },
  'Google Analytics': { dom: [/GoogleAnalyticsObject/i, /google-analytics\.com\/analytics\.js/i, /gtag\(/i], cookies: [/_ga/i, /_gid/i, /_gat/i] },
  'Google Tag Manager': { dom: [/googletagmanager\.com\/gtm\.js/i, /GTM-[A-Z0-9]+/i] },
  'Facebook Pixel': { dom: [/connect\.facebook\.net\/en_US\/fbevents\.js/i, /fbq\('init'/i], cookies: [/_fbp/i] },
  'Hotjar': { dom: [/static\.hotjar\.com\/c\/hotjar-/i, /hj\('hjSettings'/i], cookies: [/_hjSession_/i, /_hjIncludedInSessionSample/i] }
};
const WAF_SIGNATURES = {
  'Cloudflare': { headers: ['cf-ray', 'server'], regex: /cloudflare/i },
  'Akamai': { headers: ['x-akamai-transformed', 'server'], regex: /akamai/i },
  'Sucuri': { headers: ['x-sucuri-id', 'x-sucuri-cache'], regex: /sucuri/i },
  'Imperva/Incapsula': { headers: ['x-iinfo', 'incap_ses', 'visid_incap'], regex: /incapsula|imperva/i },
  'ModSecurity': { headers: ['server'], regex: /mod_security|modsecurity/i },
  'AWS WAF': { headers: ['x-amzn-requestid', 'server'], regex: /awswaf/i },
  'F5 BIG-IP': { headers: ['x-cprealm', 'server'], regex: /big-ip|f5/i }
};
 const SECRET_PATTERNS = {
  'AWS Access Key': /\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
  'Google API Key': /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  'Stripe Live Key': /\bsk_live_[0-9a-zA-Z]{24}\b/g,
  'Stripe Test Key': /\bsk_test_[0-9a-zA-Z]{24}\b/g,
  'Firebase URL': /\bhttps:\/\/[a-z0-9-]+\.firebaseio\.com\b/gi,
  'Internal IP': /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
  'Staging/Dev Domain': /\b(?:[a-zA-Z0-9-]+\.)*(?:staging|dev|test|uat|sandbox)\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b/gi
};
 const COMMON_SITEMAPS = [
  '/sitemap.xml', 
  '/sitemap_index.xml', 
  '/sitemaps.xml', 
  '/api/sitemap'
];
module.exports = {
  BROWSER_PROFILES,
  COMMON_PORTS,
  FUZZ_TARGETS,
  MAIL_PORTS,
  DB_PORTS,
  ADMIN_PORTS,
  INFRA_PORTS,
  TLD_PERMUTATIONS,
  WHITELIST_DOMAINS,
  DB_PROBES,
  COMMON_UDP_PORTS,
  UDP_PAYLOADS,
  SMB_NEGOTIATE_PAYLOAD,
  TECH_SIGNATURES_PRO, 
  COMMON_SITEMAPS, 
  SECRET_PATTERNS, 
  WAF_SIGNATURES
};