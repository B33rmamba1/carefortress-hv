/**
 * CareFortress Spider Trap - Cloudflare Worker
 *
 * Intercepts requests to known scanner/attacker paths and returns an
 * infinite maze of randomly-generated links (seeded by URL path so the
 * same path always produces the same links, making the maze feel real
 * to a crawler).
 *
 * Legitimate paths pass through to Cloudflare Pages unchanged.
 *
 * Log events are structured as Wazuh-compatible JSON, ready for a
 * Filebeat HTTP input endpoint when Phase 4 SIEM is deployed.
 *
 * Based on the spider trap concept by John Strand / Black Hills Information Security.
 * Adapted for Cloudflare Workers (JavaScript, no artificial delay due to 10ms CPU limit).
 *
 * Deployment:
 *   1. wrangler login
 *   2. wrangler deploy
 *   Or paste into Cloudflare Dashboard > Workers & Pages > Create Worker
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CONFIG = {
  // Links per generated page (min, max)
  LINKS_PER_PAGE: [5, 10],

  // Length of each generated link segment (min, max)
  LENGTH_OF_LINKS: [3, 20],

  // Characters to compose random link paths from
  CHAR_SPACE: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-',

  // Wazuh Filebeat HTTP input endpoint (set once Phase 4 SIEM is live)
  // Format: "https://your-wazuh-host:9200/filebeat-..." or Filebeat HTTP input
  // Leave null to skip Wazuh forwarding until SIEM is deployed
  WAZUH_ENDPOINT: null,

  // Optional: Wazuh API key or basic auth token if required
  WAZUH_AUTH: null,
};

// ---------------------------------------------------------------------------
// Decoy path patterns - any request matching these goes to the spider trap
// High-signal paths: no legitimate user or browser should ever request these
// ---------------------------------------------------------------------------

const DECOY_EXACT = new Set([
  // robots.txt - trapped with a fake file full of enticing disallow paths
  // that all lead deeper into the maze (see generateRobotsTxt below)
  '/robots.txt',

  // sitemap.xml - 13 hits in carefortress.dev logs, clearly scanner-driven.
  // A legitimate site would serve a real sitemap; carefortress.dev has no SEO need.
  // Trapped as a plain HTML maze page.
  '/sitemap.xml',

  // Environment / credentials
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.env.backup',
  '/.env.bak',
  '/.aws/credentials',
  '/.aws/config',

  // Git exposure
  '/.git/config',
  '/.git/HEAD',
  '/.gitignore',

  // Config file fishing
  '/config.json',
  '/config.php',
  '/config.yaml',
  '/config.yml',
  '/configuration.json',
  '/settings.json',
  '/secrets.json',
  '/database.yml',
  '/db.php',

  // Spring Boot actuator (Java microservice probing)
  '/actuator/env',
  '/actuator/health',
  '/actuator/info',
  '/actuator/mappings',
  '/actuator/beans',
  '/env',

  // PHP backdoor / CMS probing
  '/h2.php',
  '/wp-login.php',
  '/wp-admin',
  '/wp-admin/',
  '/xmlrpc.php',
  '/admin',
  '/admin/',
  '/administrator',
  '/administrator/',
  '/phpmyadmin',
  '/phpmyadmin/',
  '/mysql',
  '/sql',

  // Windows Live Writer / WordPress manifest (seen in carefortress.dev logs)
  '/wlwmanifest.xml',

  // SSH / credentials
  '/.ssh/id_rsa',
  '/.ssh/id_ed25519',
  '/.ssh/authorized_keys',

  // Other common high-signal paths
  '/server-status',
  '/server-info',
  '/.htaccess',
  '/.htpasswd',
  '/web.config',
  '/crossdomain.xml',
  '/clientaccesspolicy.xml',
  '/info.php',
  '/phpinfo.php',
  '/test.php',
  '/shell.php',
  '/cmd.php',
  '/backup.zip',
  '/backup.sql',
  '/dump.sql',
  '/db.sql',
  '/README.md',
  '/CHANGELOG.md',
  '/LICENSE.txt',
  '/composer.json',
  '/composer.lock',
  '/package.json',
  '/package-lock.json',
  '/Dockerfile',
  '/docker-compose.yml',
  '/Makefile',
]);

// Decoy path prefixes - any path starting with these goes to the trap
const DECOY_PREFIXES = [
  '/wp-includes/',
  '/wp-content/',
  '/wp-admin/',
  '//cms/',
  '//web/',
  '//news/',
  '//2019/',
  '//2020/',
  '//2021/',
  '//2022/',
  '//2023/',
  '//2024/',
  '//2025/',
  '/admin/',
  '/administrator/',
  '/phpmyadmin/',
  '/actuator/',
  '/.git/',
  '/.env',
  '/.aws/',
  '/.ssh/',
];

// ---------------------------------------------------------------------------
// Seeded pseudo-random number generator
// Deterministic so the same URL path always produces the same maze page.
// Uses a simple mulberry32 PRNG seeded from a hash of the path string.
// ---------------------------------------------------------------------------

function hashString(str) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash;
}

function makeRng(seed) {
  let s = seed >>> 0;
  return function () {
    s += 0x6d2b79f5;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng, min, max) {
  return min + Math.floor(rng() * (max - min + 1));
}

// ---------------------------------------------------------------------------
// Generate a spider trap page seeded by the request path
// ---------------------------------------------------------------------------

function generateTrapPage(path) {
  const seed = hashString(path);
  const rng = makeRng(seed);
  const numLinks = randInt(rng, CONFIG.LINKS_PER_PAGE[0], CONFIG.LINKS_PER_PAGE[1]);

  let links = '';
  for (let i = 0; i < numLinks; i++) {
    const len = randInt(rng, CONFIG.LENGTH_OF_LINKS[0], CONFIG.LENGTH_OF_LINKS[1]);
    let segment = '';
    for (let c = 0; c < len; c++) {
      const idx = Math.floor(rng() * CONFIG.CHAR_SPACE.length);
      segment += CONFIG.CHAR_SPACE[idx];
    }
    // All generated links are relative paths - every one is a valid new trap entry
    const href = '/' + segment;
    links += `<a href="${href}">${href}</a><br>\n`;
  }

  return `<html>\n<head><title>CareFortress</title></head>\n<body>\n${links}</body>\n</html>`;
}

// ---------------------------------------------------------------------------
// Log a trap hit as Wazuh-compatible JSON
// Forwards to Wazuh Filebeat HTTP input if configured; console.log otherwise
// ---------------------------------------------------------------------------

async function logTrapHit(request, path) {
  const event = {
    timestamp: new Date().toISOString(),
    event_type: 'SPIDER_TRAP_HIT',
    source: 'carefortress-cloudflare-worker',
    severity: 'medium',
    path: path,
    method: request.method,
    source_ip: request.headers.get('CF-Connecting-IP') || 'unknown',
    user_agent: request.headers.get('User-Agent') || 'unknown',
    referer: request.headers.get('Referer') || 'none',
    country: request.headers.get('CF-IPCountry') || 'unknown',
    ray_id: request.headers.get('CF-Ray') || 'unknown',
    asn: request.headers.get('CF-IPCountry') || 'unknown',
    msg: `Spider trap triggered by ${request.headers.get('CF-Connecting-IP')} on path ${path}`,
  };

  // Always log to Cloudflare Worker console (visible in wrangler tail / dashboard logs)
  console.log(JSON.stringify(event));

  // Forward to Wazuh Filebeat HTTP input once Phase 4 SIEM is deployed
  if (CONFIG.WAZUH_ENDPOINT) {
    const headers = { 'Content-Type': 'application/json' };
    if (CONFIG.WAZUH_AUTH) {
      headers['Authorization'] = `Bearer ${CONFIG.WAZUH_AUTH}`;
    }
    try {
      await fetch(CONFIG.WAZUH_ENDPOINT, {
        method: 'POST',
        headers,
        body: JSON.stringify(event),
      });
    } catch (err) {
      // Never let logging failure affect the trap response
      console.error('Wazuh forward failed:', err.message);
    }
  }
}

// ---------------------------------------------------------------------------
// Path matching
// ---------------------------------------------------------------------------

function isDecoyPath(path) {
  // Normalize double slashes for comparison
  const normalized = path.replace(/\/\/+/g, '//');

  if (DECOY_EXACT.has(path)) return true;

  for (const prefix of DECOY_PREFIXES) {
    if (path.startsWith(prefix) || normalized.startsWith(prefix)) return true;
  }

  // Catch common extension-based fishing regardless of path
  const extPatterns = [
    /\.php$/i,
    /\.asp$/i,
    /\.aspx$/i,
    /\.jsp$/i,
    /\.cgi$/i,
    /wlwmanifest\.xml$/i,
    /xmlrpc\.php$/i,
  ];
  for (const pattern of extPatterns) {
    if (pattern.test(path)) return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// Generate a fake robots.txt full of enticing Disallow paths
// All listed paths are themselves trap entries - the attacker mines the file
// and gets a curated list of "hidden" paths that lead deeper into the maze.
// Seeded by date so it changes monthly, making it look actively maintained.
// ---------------------------------------------------------------------------

function generateRobotsTxt() {
  const now = new Date();
  // Seed changes monthly so the file looks like it's being updated
  const seed = hashString(`${now.getFullYear()}-${now.getMonth()}`);
  const rng = makeRng(seed);

  // Pool of enticing-looking paths that attackers love to see in Disallow
  const enticingPaths = [
    '/admin',
    '/admin/dashboard',
    '/admin/users',
    '/admin/config',
    '/admin/backup',
    '/administrator',
    '/api/internal',
    '/api/v1/admin',
    '/api/v1/users',
    '/api/v1/config',
    '/api/keys',
    '/api/secrets',
    '/backup',
    '/backups',
    '/db',
    '/database',
    '/config',
    '/configs',
    '/internal',
    '/private',
    '/secret',
    '/secrets',
    '/staging',
    '/dev',
    '/development',
    '/test',
    '/testing',
    '/beta',
    '/dashboard',
    '/portal',
    '/management',
    '/manage',
    '/console',
    '/control',
    '/cp',
    '/panel',
    '/staff',
    '/employees',
    '/finance',
    '/billing',
    '/payments',
    '/keys',
    '/credentials',
    '/tokens',
    '/certs',
    '/certificates',
    '/logs',
    '/audit',
    '/debug',
    '/trace',
    '/metrics',
    '/health/internal',
    '/actuator',
    '/actuator/env',
    '/actuator/beans',
    '/env',
    '/setup',
    '/install',
    '/wp-admin',
    '/phpmyadmin',
    '/.git',
    '/.env',
    '/.aws',
    '/.ssh',
    '/tmp',
    '/cache',
    '/uploads/private',
    '/files/internal',
    '/export',
    '/reports',
    '/analytics/internal',
    '/system',
    '/sys',
    '/server',
    '/infrastructure',
  ];

  // Pick a random subset to show this month (makes it look curated, not exhaustive)
  const shuffled = [...enticingPaths].sort(() => rng() - 0.5);
  const selected = shuffled.slice(0, 20 + Math.floor(rng() * 10));

  // Build the fake robots.txt
  let content = '# robots.txt for carefortress.dev\n';
  content += '# Generated: ' + now.toISOString().split('T')[0] + '\n\n';
  content += 'User-agent: *\n';

  // Allow a few innocuous paths to make it look real
  content += 'Allow: /\n';
  content += 'Allow: /index.html\n\n';

  // The enticing disallows - all trap paths
  for (const path of selected) {
    content += `Disallow: ${path}\n`;
  }

  content += '\n# Sitemap\n';
  content += 'Sitemap: https://carefortress.dev/sitemap.xml\n';

  return content;
}

// ---------------------------------------------------------------------------
// Main Worker handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (isDecoyPath(path)) {
      // Log the hit asynchronously - don't block the response
      ctx.waitUntil(logTrapHit(request, path));

      // robots.txt gets a special fake response - plain text with enticing
      // Disallow paths that all lead into the spider trap maze
      if (path === '/robots.txt') {
        return new Response(generateRobotsTxt(), {
          status: 200,
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-store',
          },
        });
      }

      // All other decoy paths return the infinite HTML maze
      return new Response(generateTrapPage(path), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      });
    }

    // Legitimate path - pass through to Cloudflare Pages origin unchanged
    return fetch(request);
  },
};
