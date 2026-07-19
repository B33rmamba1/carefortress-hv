/**
 * CareFortress Spider Trap - Cloudflare Worker (v2 - Canary Integration)
 *
 * Intercepts requests to known scanner/attacker paths. High-value paths
 * (/.env, /.git/config, /config.json, /.ssh/id_rsa) return realistic
 * honeypot content with embedded canary tracking URLs unique per visitor.
 * All other trap paths return the infinite maze.
 *
 * Canary callbacks use single-level subdomains:
 *   repo-{tokenId}.carefortress.dev  → fake git remote clone
 *   int-{tokenId}.carefortress.dev   → fake database hostname resolution
 *
 * Token IDs are deterministic per visitor IP (8-char hex hash), so the
 * same attacker always gets the same tokens across visits.
 *
 * All events POST to webhook.carefortress.dev → Cloudflare tunnel →
 * VM 103 listener → Wazuh SIEM.
 *
 * Based on the spider trap concept by John Strand / BHIS.
 * Adapted for Cloudflare Workers.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const CONFIG = {
  LINKS_PER_PAGE: [5, 10],
  LENGTH_OF_LINKS: [3, 20],
  CHAR_SPACE: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-',
  WAZUH_ENDPOINT: 'https://webhook.carefortress.dev',
  WAZUH_AUTH: null,
};


// ---------------------------------------------------------------------------
// AWS Canary Token Pool (Thinkst canarytokens.org)
// Each token fires an alert via CloudTrail + webhook on any AWS API call.
// Visitor IP hash selects a pool slot deterministically.
// ---------------------------------------------------------------------------

const AWS_CANARY_POOL = [
  // -----------------------------------------------------------------------
  // POOL KEYS REDACTED FROM REPOSITORY
  // Real Thinkst canarytokens.org AWS key pairs are configured only in
  // the deployed Cloudflare Worker. 20 slots, each with a unique AKIA key
  // and secret that fires a CloudTrail alert on any AWS API call.
  // To populate: generate tokens at canarytokens.org/generate (type: AWS)
  // and add them here as { id: N, key: "AKIA...", secret: "..." }
  // -----------------------------------------------------------------------
  // { id:  1, key: "AKIA_REDACTED_01", secret: "REDACTED_01" },
  // { id:  2, key: "AKIA_REDACTED_02", secret: "REDACTED_02" },
  // ... through slot 20
];

function getCanaryAwsKeys(tokenId) {
  const idx = parseInt(tokenId, 16) % AWS_CANARY_POOL.length;
  return AWS_CANARY_POOL[idx];
}

// ---------------------------------------------------------------------------
// High-value paths that get honeypot content instead of maze HTML
// Each maps to a function that generates realistic fake content
// ---------------------------------------------------------------------------

const HONEYPOT_PATHS = {
  '/.env':                generateFakeEnv,
  '/.env.local':          generateFakeEnv,
  '/.env.production':     generateFakeEnv,
  '/.env.backup':         generateFakeEnv,
  '/.env.bak':            generateFakeEnv,
  '/.aws/credentials':    generateFakeAwsCreds,
  '/.aws/config':         generateFakeAwsConfig,
  '/.git/config':         generateFakeGitConfig,
  '/.git/HEAD':           generateFakeGitHead,
  '/config.json':         generateFakeConfigJson,
  '/config.yml':          generateFakeConfigYml,
  '/config.yaml':         generateFakeConfigYml,
  '/configuration.json':  generateFakeConfigJson,
  '/settings.json':       generateFakeSettingsJson,
  '/database.yml':        generateFakeDatabaseYml,
  '/.ssh/id_rsa':         generateFakeSshKey,
  '/.ssh/id_ed25519':     generateFakeSshKeyEd25519,
  '/.ssh/authorized_keys':generateFakeAuthorizedKeys,
  '/.ssh/config':         generateFakeSshConfig,
  '/docker-compose.yml':  generateFakeDockerCompose,
  '/Dockerfile':          generateFakeDockerfile,
};

// ---------------------------------------------------------------------------
// Decoy path patterns (unchanged from v1)
// ---------------------------------------------------------------------------

const DECOY_EXACT = new Set([
  '/robots.txt', '/sitemap.xml',
  '/.env', '/.env.local', '/.env.production', '/.env.backup', '/.env.bak',
  '/.aws/credentials', '/.aws/config',
  '/.git/config', '/.git/HEAD', '/.gitignore',
  '/config.json', '/config.php', '/config.yaml', '/config.yml',
  '/configuration.json', '/settings.json', '/secrets.json',
  '/database.yml', '/db.php',
  '/actuator/env', '/actuator/health', '/actuator/info',
  '/actuator/mappings', '/actuator/beans', '/env',
  '/h2.php', '/wp-login.php', '/wp-admin', '/wp-admin/',
  '/xmlrpc.php', '/admin', '/admin/', '/administrator', '/administrator/',
  '/phpmyadmin', '/phpmyadmin/', '/mysql', '/sql',
  '/wlwmanifest.xml',
  '/.ssh/id_rsa', '/.ssh/id_ed25519', '/.ssh/authorized_keys', '/.ssh/config',
  '/server-status', '/server-info',
  '/.htaccess', '/.htpasswd', '/web.config',
  '/crossdomain.xml', '/clientaccesspolicy.xml',
  '/info.php', '/phpinfo.php', '/test.php', '/shell.php', '/cmd.php',
  '/backup.zip', '/backup.sql', '/dump.sql', '/db.sql',
  '/README.md', '/CHANGELOG.md', '/LICENSE.txt',
  '/composer.json', '/composer.lock',
  '/package.json', '/package-lock.json',
  '/Dockerfile', '/docker-compose.yml', '/Makefile',
]);

const DECOY_PREFIXES = [
  '/wp-includes/', '/wp-content/', '/wp-admin/',
  '//cms/', '//web/', '//news/',
  '//2019/', '//2020/', '//2021/', '//2022/', '//2023/', '//2024/', '//2025/',
  '/admin/', '/administrator/', '/phpmyadmin/',
  '/actuator/', '/.git/', '/.env', '/.aws/', '/.ssh/',
];

// ---------------------------------------------------------------------------
// Token ID generation - deterministic per visitor IP
// ---------------------------------------------------------------------------

function generateTokenId(ip) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < ip.length; i++) {
    hash ^= ip.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

// ---------------------------------------------------------------------------
// Honeypot content generators
// Each takes a tokenId and returns { body: string, contentType: string }
// ---------------------------------------------------------------------------

function generateFakeEnv(tokenId) {
  const creds = getCanaryAwsKeys(tokenId);
  const body = `# CareFortress Production Environment
# Last updated: 2026-06-15

APP_NAME=carefortress
APP_ENV=production
APP_DEBUG=false
APP_URL=https://carefortress.dev

DB_CONNECTION=pgsql
DB_HOST=int-${tokenId}.carefortress.dev
DB_PORT=5432
DB_DATABASE=carefortress_prod
DB_USERNAME=cf_admin
DB_PASSWORD=kP9$vLm2!xQwR7nT

REDIS_HOST=int-${tokenId}.carefortress.dev
REDIS_PASSWORD=rEdIs_S3cur3_2026!
REDIS_PORT=6379

AWS_ACCESS_KEY_ID=${creds.key}
AWS_SECRET_ACCESS_KEY=${creds.secret}
AWS_DEFAULT_REGION=us-east-2
AWS_BUCKET=carefortress-prod-assets

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_USERNAME=postmaster@carefortress.dev
MAIL_PASSWORD=mg_api_k3y_2026_pr0d

JWT_SECRET=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.c2VjcmV0
JWT_TTL=3600

STRIPE_KEY=pk_live_51H7xKGHIJKLMNOPQRSTUVW
STRIPE_SECRET=sk_live_51H7xyzABCDEFGHIJKLMNOP

SENTRY_DSN=https://abc123@o456.ingest.sentry.io/789

# Internal API
API_GATEWAY_URL=https://int-${tokenId}.carefortress.dev:8443/api/v1
API_GATEWAY_KEY=cgw_prod_4f8a2b1c9d3e7f6a
`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

function generateFakeAwsCreds(tokenId) {
  const creds = getCanaryAwsKeys(tokenId);
  // Use a second pool slot for the "staging" profile
  const stagingIdx = (parseInt(tokenId, 16) + 7) % AWS_CANARY_POOL.length;
  const stagingCreds = AWS_CANARY_POOL[stagingIdx];
  const body = `[default]
aws_access_key_id = ${creds.key}
aws_secret_access_key = ${creds.secret}

[carefortress-prod]
aws_access_key_id = ${creds.key}
aws_secret_access_key = ${creds.secret}
region = us-east-2

[carefortress-staging]
aws_access_key_id = ${stagingCreds.key}
aws_secret_access_key = ${stagingCreds.secret}
region = us-east-2
`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

function generateFakeAwsConfig(tokenId) {
  const body = `[default]
region = us-east-1
output = json

[profile carefortress-prod]
region = us-east-1
output = json

[profile carefortress-staging]
region = us-east-2
output = json
`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

function generateFakeGitConfig(tokenId) {
  const body = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://repo-${tokenId}.carefortress.dev/carefortress/carefortress-platform.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[remote "staging"]
	url = https://repo-${tokenId}.carefortress.dev/carefortress/carefortress-staging.git
	fetch = +refs/heads/*:refs/remotes/staging/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[branch "develop"]
	remote = origin
	merge = refs/heads/develop
[user]
	name = James Smith
	email = james@carefortress.dev
`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

function generateFakeGitHead(tokenId) {
  const body = `ref: refs/heads/main\n`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

function generateFakeConfigJson(tokenId) {
  const body = JSON.stringify({
    application: {
      name: "carefortress-platform",
      version: "2.4.1",
      environment: "production"
    },
    database: {
      primary: {
        host: `int-${tokenId}.carefortress.dev`,
        port: 5432,
        name: "carefortress_prod",
        username: "cf_admin",
        password: "kP9$vLm2!xQwR7nT",
        ssl: true
      },
      replica: {
        host: `int-${tokenId}.carefortress.dev`,
        port: 5433,
        name: "carefortress_prod_ro",
        username: "cf_readonly",
        password: "r0_P4ss_2026!"
      }
    },
    redis: {
      host: `int-${tokenId}.carefortress.dev`,
      port: 6379,
      password: "rEdIs_S3cur3_2026!",
      db: 0
    },
    api: {
      gateway_url: `https://int-${tokenId}.carefortress.dev:8443/api/v1`,
      api_key: "cgw_prod_4f8a2b1c9d3e7f6a",
      rate_limit: 1000
    },
    auth: {
      jwt_secret: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.c2VjcmV0",
      token_ttl: 3600,
      refresh_ttl: 86400
    },
    storage: {
      provider: "s3",
      bucket: "carefortress-prod-assets",
      region: "us-east-1"
    }
  }, null, 2);
  return { body, contentType: 'application/json; charset=utf-8' };
}

function generateFakeConfigYml(tokenId) {
  const body = `# CareFortress Platform Configuration
# Environment: production
# Last modified: 2026-06-15

application:
  name: carefortress-platform
  version: 2.4.1
  environment: production
  debug: false

database:
  primary:
    host: int-${tokenId}.carefortress.dev
    port: 5432
    name: carefortress_prod
    username: cf_admin
    password: "kP9$vLm2!xQwR7nT"
    pool_size: 20
    ssl_mode: require
  replica:
    host: int-${tokenId}.carefortress.dev
    port: 5433
    name: carefortress_prod_ro
    username: cf_readonly
    password: "r0_P4ss_2026!"

redis:
  host: int-${tokenId}.carefortress.dev
  port: 6379
  password: "rEdIs_S3cur3_2026!"

api:
  gateway: https://int-${tokenId}.carefortress.dev:8443/api/v1
  key: cgw_prod_4f8a2b1c9d3e7f6a

logging:
  level: warn
  sentry_dsn: https://abc123@o456.ingest.sentry.io/789
`;
  return { body, contentType: 'text/yaml; charset=utf-8' };
}

function generateFakeSettingsJson(tokenId) {
  const body = JSON.stringify({
    site: {
      name: "CareFortress",
      url: "https://carefortress.dev",
      admin_email: "admin@carefortress.dev"
    },
    features: {
      maintenance_mode: false,
      api_enabled: true,
      registration_open: false
    },
    integrations: {
      ehr_endpoint: `https://int-${tokenId}.carefortress.dev:9443/ehr/v2`,
      ehr_api_key: "ehr_prod_8k2m4n6p",
      fhir_server: `https://int-${tokenId}.carefortress.dev:9444/fhir/r4`
    },
    security: {
      mfa_required: true,
      session_timeout: 1800,
      password_policy: "strong"
    }
  }, null, 2);
  return { body, contentType: 'application/json; charset=utf-8' };
}

function generateFakeDatabaseYml(tokenId) {
  const body = `# Database configuration
production:
  adapter: postgresql
  host: int-${tokenId}.carefortress.dev
  port: 5432
  database: carefortress_prod
  username: cf_admin
  password: "kP9$vLm2!xQwR7nT"
  pool: 25
  timeout: 5000
  ssl: true

staging:
  adapter: postgresql
  host: int-${tokenId}.carefortress.dev
  port: 5432
  database: carefortress_staging
  username: cf_staging
  password: "stG_P4ss_2026!"
  pool: 10

test:
  adapter: sqlite3
  database: db/test.sqlite3
`;
  return { body, contentType: 'text/yaml; charset=utf-8' };
}

function generateFakeSshKey(tokenId) {
  // Realistic-looking RSA private key (fake, not a real key)
  const body = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBHK9Fc5JdmPk0YyV7j3nR${tokenId}AABQgAAAAtzc2gtZWQyNTUxOQAA
ACBHK9Fc5JdmPk0YyV7j3nRp0AAAAED8n4bOvXpG1hZP5KL8mN2dR9xTQvFw3kJjYe6s
0AAAACZGVWZM9AY2FyZWZvcnRyZXNzLmRldg${tokenId}AAAAAECzR1v2MxhT4kpN9Xm
qW7fJb3nYvKdHGx5tPRAjLmS8ocr0VzklY+TRjJXuPedG${tokenId}AAAAFGRlcGxveUBj
YXJlZm9ydHJlc3MuZGV2AQIDBAUISSH${tokenId}FAKE
-----END OPENSSH PRIVATE KEY-----
`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

function generateFakeSshKeyEd25519(tokenId) {
  const body = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDK${tokenId}nR9xTQvFw3kJjYe6sMwAAAAtzc2gtZWQyNTUxOQAAACDK
${tokenId}PRAjLmS8ocr0VzklY+TRjJXuPedGnQAAAED8n4bOvXpG1hZP5KL8m
-----END OPENSSH PRIVATE KEY-----
`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

function generateFakeAuthorizedKeys(tokenId) {
  const body = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${tokenId}K9Fc5JdmPk0YyV7j3nRp0 deploy@carefortress.dev
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC${tokenId}xTQvFw3kJjYe6sMwR1v2MxhT4kpN9XmqW7fJb3nYvKdHGx5tPRAjLmS8ocr0VzklY admin@carefortress.dev
`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

function generateFakeSshConfig(tokenId) {
  const body = `# CareFortress SSH Config
Host carefortress-prod
    HostName int-${tokenId}.carefortress.dev
    User deploy
    IdentityFile ~/.ssh/id_ed25519
    Port 22
    ForwardAgent no

Host carefortress-staging
    HostName int-${tokenId}.carefortress.dev
    User deploy-staging
    IdentityFile ~/.ssh/id_ed25519
    Port 2222

Host carefortress-db
    HostName int-${tokenId}.carefortress.dev
    User dba
    IdentityFile ~/.ssh/id_rsa
    Port 22
    LocalForward 5432 localhost:5432
`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

function generateFakeDockerCompose(tokenId) {
  const body = `version: '3.8'

services:
  app:
    image: carefortress/platform:2.4.1
    environment:
      DATABASE_URL: postgresql://cf_admin:kP9$$vLm2!xQwR7nT@int-${tokenId}.carefortress.dev:5432/carefortress_prod
      REDIS_URL: redis://:rEdIs_S3cur3_2026!@int-${tokenId}.carefortress.dev:6379/0
      JWT_SECRET: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.c2VjcmV0
    ports:
      - "8080:8080"
    depends_on:
      - redis

  worker:
    image: carefortress/worker:2.4.1
    environment:
      DATABASE_URL: postgresql://cf_admin:kP9$$vLm2!xQwR7nT@int-${tokenId}.carefortress.dev:5432/carefortress_prod
      REDIS_URL: redis://:rEdIs_S3cur3_2026!@int-${tokenId}.carefortress.dev:6379/0
    command: ["celery", "-A", "carefortress", "worker", "--loglevel=info"]

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass rEdIs_S3cur3_2026!
    ports:
      - "6379:6379"
`;
  return { body, contentType: 'text/yaml; charset=utf-8' };
}

function generateFakeDockerfile(tokenId) {
  const body = `FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Configure for production
ENV APP_ENV=production
ENV DATABASE_HOST=int-${tokenId}.carefortress.dev
ENV DATABASE_PORT=5432
ENV DATABASE_NAME=carefortress_prod

EXPOSE 8080

CMD ["gunicorn", "carefortress.wsgi:application", "--bind", "0.0.0.0:8080", "--workers", "4"]
`;
  return { body, contentType: 'text/plain; charset=utf-8' };
}

// ---------------------------------------------------------------------------
// Seeded PRNG (unchanged from v1)
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
// Maze page generator (unchanged from v1)
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
    const href = '/' + segment;
    links += `<a href="${href}">${href}</a><br>\n`;
  }

  return `<html>\n<head><title>CareFortress</title></head>\n<body>\n${links}</body>\n</html>`;
}

// ---------------------------------------------------------------------------
// robots.txt generator (unchanged from v1)
// ---------------------------------------------------------------------------

function generateRobotsTxt() {
  const now = new Date();
  const seed = hashString(`${now.getFullYear()}-${now.getMonth()}`);
  const rng = makeRng(seed);

  const enticingPaths = [
    '/admin', '/admin/dashboard', '/admin/users', '/admin/config', '/admin/backup',
    '/administrator', '/api/internal', '/api/v1/admin', '/api/v1/users',
    '/api/v1/config', '/api/keys', '/api/secrets', '/backup', '/backups',
    '/db', '/database', '/config', '/configs', '/internal', '/private',
    '/secret', '/secrets', '/staging', '/dev', '/development', '/test',
    '/testing', '/dashboard', '/portal', '/management', '/console',
    '/control', '/panel', '/staff', '/finance', '/billing', '/payments',
    '/keys', '/credentials', '/tokens', '/certs', '/logs', '/audit',
    '/debug', '/metrics', '/health/internal', '/actuator', '/env',
    '/setup', '/install', '/wp-admin', '/phpmyadmin', '/.git', '/.env',
    '/.aws', '/.ssh', '/tmp', '/uploads/private', '/export', '/reports',
    '/system', '/server', '/infrastructure',
  ];

  const shuffled = [...enticingPaths].sort(() => rng() - 0.5);
  const selected = shuffled.slice(0, 20 + Math.floor(rng() * 10));

  let content = '# robots.txt for carefortress.dev\n';
  content += '# Updated: ' + now.toISOString().split('T')[0] + '\n\n';
  content += 'User-agent: *\n';
  content += 'Allow: /\n';
  content += 'Allow: /index.html\n\n';
  for (const path of selected) {
    content += `Disallow: ${path}\n`;
  }
  content += '\n# Sitemap\n';
  content += 'Sitemap: https://carefortress.dev/sitemap.xml\n';
  return content;
}

// ---------------------------------------------------------------------------
// Logging - POST to Wazuh webhook
// ---------------------------------------------------------------------------

async function logTrapHit(request, path, extras = {}) {
  const event = {
    timestamp: new Date().toISOString(),
    event_type: extras.event_type || 'SPIDER_TRAP_HIT',
    source: 'carefortress-cloudflare-worker',
    severity: extras.severity || 'medium',
    path: path,
    method: request.method,
    source_ip: request.headers.get('CF-Connecting-IP') || 'unknown',
    user_agent: request.headers.get('User-Agent') || 'unknown',
    referer: request.headers.get('Referer') || 'none',
    country: request.headers.get('CF-IPCountry') || 'unknown',
    ray_id: request.headers.get('CF-Ray') || 'unknown',
    asn: request.headers.get('CF-IPCountry') || 'unknown',
    msg: `Spider trap triggered by ${request.headers.get('CF-Connecting-IP')} on path ${path}`,
    ...extras,
  };

  console.log(JSON.stringify(event));

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
      console.error('Wazuh forward failed:', err.message);
    }
  }
}

// ---------------------------------------------------------------------------
// Path matching (unchanged from v1)
// ---------------------------------------------------------------------------

function isDecoyPath(path) {
  const normalized = path.replace(/\/\/+/g, '//');
  if (DECOY_EXACT.has(path)) return true;
  for (const prefix of DECOY_PREFIXES) {
    if (path.startsWith(prefix) || normalized.startsWith(prefix)) return true;
  }
  const extPatterns = [
    /\.php$/i, /\.asp$/i, /\.aspx$/i, /\.jsp$/i,
    /\.cgi$/i, /wlwmanifest\.xml$/i, /xmlrpc\.php$/i,
  ];
  for (const pattern of extPatterns) {
    if (pattern.test(path)) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Main Worker handler
// ---------------------------------------------------------------------------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (isDecoyPath(path)) {
      const visitorIp = request.headers.get('CF-Connecting-IP') || 'unknown';
      const tokenId = generateTokenId(visitorIp);

      // Check if this is a high-value honeypot path
      const honeypotGen = HONEYPOT_PATHS[path];

      if (honeypotGen) {
        // Log with canary metadata
        ctx.waitUntil(logTrapHit(request, path, {
          event_type: 'CANARY_SERVED',
          severity: 'high',
          token_id: tokenId,
          canary_domains: [
            `repo-${tokenId}.carefortress.dev`,
            `int-${tokenId}.carefortress.dev`,
          ],
          aws_pool_slot: parseInt(tokenId, 16) % 20 + 1,
        }));

        const { body, contentType } = honeypotGen(tokenId);
        return new Response(body, {
          status: 200,
          headers: {
            'Content-Type': contentType,
            'Cache-Control': 'no-store',
          },
        });
      }

      // robots.txt
      if (path === '/robots.txt') {
        ctx.waitUntil(logTrapHit(request, path));
        return new Response(generateRobotsTxt(), {
          status: 200,
          headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-store',
          },
        });
      }

      // All other decoy paths - maze HTML
      ctx.waitUntil(logTrapHit(request, path));
      return new Response(generateTrapPage(path), {
        status: 200,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      });
    }

    // Legitimate path - pass through to Cloudflare Pages
    return fetch(request);
  },
};
