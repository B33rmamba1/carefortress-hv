#!/usr/bin/env python3
"""
CareFortress Management Dashboard API
FastAPI REST interface for hypervisor security controls.

Endpoints:
  GET  /health           -- liveness check (no auth)
  POST /auth/token       -- obtain JWT
  GET  /vms              -- list VM status
  GET  /logs             -- recent audit chain entries
  GET  /attestation      -- run TPM PCR attestation
  GET  /policy           -- current inter-VM policy
  POST /policy           -- update inter-VM policy rule

Security:
  - JWT Bearer token auth on all endpoints except /health and /auth/token
  - HTTPS only (TLS cert in dashboard/certs/)
  - Rate limiting: 60 req/min per IP on auth, 120 req/min on data endpoints
  - CORS disabled (same-host access only)

Run:
  python3 dashboard/api.py

Or via uvicorn directly:
  uvicorn dashboard.api:app --ssl-keyfile dashboard/certs/key.pem \
      --ssl-certfile dashboard/certs/cert.pem --host 0.0.0.0 --port 8443
"""

import os
import json
import subprocess
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ── Configuration ─────────────────────────────────────────────────────
REPO_ROOT   = os.path.expanduser('~/carefortress-hv')
LOG_FILE    = os.path.join(REPO_ROOT, 'logs/audit-chain.log')
POLICY_FILE = os.path.join(REPO_ROOT, 'policy/network-policy.json')
CERT_FILE   = os.path.join(REPO_ROOT, 'dashboard/certs/cert.pem')
KEY_FILE    = os.path.join(REPO_ROOT, 'dashboard/certs/key.pem')

SECRET_KEY  = os.environ.get('CF_SECRET_KEY', 'CHANGE_ME_IN_PRODUCTION_USE_ENV_VAR')
ALGORITHM   = 'HS256'
TOKEN_EXPIRE_MINUTES = 60

# ── User store (replace with proper secrets management in production) ──
# Passwords are bcrypt hashed -- generate with:
#   python3 -c "from passlib.context import CryptContext; print(CryptContext(['bcrypt']).hash('yourpassword'))"
USERS = {
    'admin': {
        'username': 'admin',
        'hashed_password': '$2b$12$UOqMpyyLPM.E3CkDJD73cu50NNb3nIWQNE827MStQ1ryVrwp2qMvK',
        'role': 'admin',
    }
}

# ── VM definitions ─────────────────────────────────────────────────────
VMS = ['medical-vm', 'mgmt-vm', 'audit-vm']

# ── App setup ─────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title='CareFortress Management API',
    description='Hypervisor security controls for legacy medical devices',
    version='0.1.0',
    docs_url=None,  # Disabled -- enable locally for development only
    redoc_url=None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Request body size limit ───────────────────────────────────────────
@app.middleware("http")
async def limit_body_size(request, call_next):
    max_body = 64 * 1024  # 64KB
    if request.headers.get("content-length"):
        if int(request.headers["content-length"]) > max_body:
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"}
            )
    return await call_next(request)


# ── Security headers middleware ───────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    return response


pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/auth/token')

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# ── Auth helpers ──────────────────────────────────────────────────────
def verify_password(plain, hashed):
    import bcrypt
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False

def create_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=TOKEN_EXPIRE_MINUTES))
    to_encode.update({'exp': expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Invalid or expired token',
        headers={'WWW-Authenticate': 'Bearer'},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = USERS.get(username)
    if user is None:
        raise credentials_exception
    return user

# ── Pydantic models ───────────────────────────────────────────────────
class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

class VMStatus(BaseModel):
    name: str
    state: str
    snapshot_count: int

class LogEntry(BaseModel):
    collected_ts: str
    source_vm: str
    event_type: str
    chain_hash: str

class AttestationResult(BaseModel):
    timestamp: str
    pcrs_checked: int
    matches: int
    deviations: int
    passed: bool
    details: List[str]

class PolicyRule(BaseModel):
    rule_id: str
    src_vm: str
    dst_vm: str
    protocol: str
    port: Optional[int]
    action: str
    enabled: bool

class PolicyUpdateRequest(BaseModel):
    rule_id: str
    enabled: bool

# ── Helpers ───────────────────────────────────────────────────────────
def run_virsh(args):
    try:
        result = subprocess.run(
            ['virsh'] + args,
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), 1

def get_vm_state(vm_name):
    out, rc = run_virsh(['domstate', vm_name])
    return out if rc == 0 else 'unknown'

def get_snapshot_count(vm_name):
    out, rc = run_virsh(['snapshot-list', vm_name, '--count'])
    try:
        return int(out.strip())
    except Exception:
        return 0

def read_log_tail(n=50):
    entries = []
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
        for line in lines[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                payload = entry.get('payload', {})
                event_type = (
                    payload.get('type') or
                    payload.get('source') or
                    'unknown'
                )
                entries.append(LogEntry(
                    collected_ts=entry.get('collected_ts', ''),
                    source_vm=entry.get('source_vm', ''),
                    event_type=str(event_type),
                    chain_hash=entry.get('chain_hash', '')[:16] + '...',
                ))
            except Exception:
                continue
    except Exception as e:
        logging.error(f'Log read error: {e}')
    return entries

def run_attestation():
    script = os.path.join(REPO_ROOT, 'scripts/attest-pcr.py')
    try:
        result = subprocess.run(
            ['python3', script],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout + result.stderr
        lines = [l.strip() for l in output.splitlines() if l.strip()]

        pcrs_checked = 0
        matches = 0
        deviations = 0
        passed = False
        details = []

        for line in lines:
            if 'PCRs checked' in line:
                parts = line.split('|')
                for p in parts:
                    p = p.strip()
                    if 'PCRs checked' in p:
                        try: pcrs_checked = int(p.split(':')[1].strip())
                        except: pass
                    if 'Matches' in p:
                        try: matches = int(p.split(':')[1].strip())
                        except: pass
                    if 'Deviations' in p:
                        try: deviations = int(p.split(':')[1].strip())
                        except: pass
            if 'PASSED' in line:
                passed = True
            if 'PCR' in line and ('Baseline' in line or 'Current' in line):
                details.append(line)

        return AttestationResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            pcrs_checked=pcrs_checked,
            matches=matches,
            deviations=deviations,
            passed=passed,
            details=details,
        )
    except Exception as e:
        return AttestationResult(
            timestamp=datetime.now(timezone.utc).isoformat(),
            pcrs_checked=0, matches=0, deviations=0, passed=False,
            details=[f'Attestation error: {str(e)}'],
        )

def load_policy():
    try:
        with open(POLICY_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}

def save_policy(policy):
    with open(POLICY_FILE, 'w') as f:
        json.dump(policy, f, indent=2)

# ── Routes ─────────────────────────────────────────────────────────────
@app.get('/health')
async def health():
    return {'status': 'ok', 'service': 'CareFortress Management API', 'version': '0.1.0'}

@app.post('/auth/token', response_model=Token)
@limiter.limit('10/minute')
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    user = USERS.get(form_data.username)
    if not user or not verify_password(form_data.password, user['hashed_password']):
        logging.warning(f'Failed login attempt for user: {form_data.username}')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Incorrect username or password',
            headers={'WWW-Authenticate': 'Bearer'},
        )
    token = create_token({'sub': user['username'], 'role': user['role']})
    logging.info(f'Successful login: {form_data.username}')
    return Token(access_token=token, token_type='bearer', expires_in=TOKEN_EXPIRE_MINUTES * 60)

@app.get('/vms', response_model=List[VMStatus])
@limiter.limit('60/minute')
async def list_vms(request: Request, current_user=Depends(get_current_user)):
    results = []
    for vm in VMS:
        state = get_vm_state(vm)
        snaps = get_snapshot_count(vm)
        results.append(VMStatus(name=vm, state=state, snapshot_count=snaps))
    return results

@app.get('/logs', response_model=List[LogEntry])
@limiter.limit('30/minute')
async def get_logs(request: Request, n: int = 50, current_user=Depends(get_current_user)):
    if n > 500:
        n = 500
    return read_log_tail(n)

@app.get('/attestation', response_model=AttestationResult)
@limiter.limit('10/minute')
async def get_attestation(request: Request, current_user=Depends(get_current_user)):
    return run_attestation()

@app.get('/policy', response_model=dict)
@limiter.limit('60/minute')
async def get_policy(request: Request, current_user=Depends(get_current_user)):
    return load_policy()

@app.post('/policy')
@limiter.limit('20/minute')
async def update_policy(
    request: Request,
    update: PolicyUpdateRequest,
    current_user=Depends(get_current_user)
):
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail='Admin role required')
    policy = load_policy()
    rules = policy.get('rules', [])
    found = False
    for rule in rules:
        if rule.get('id') == update.rule_id:
            rule['enabled'] = update.enabled
            found = True
            break
    if not found:
        raise HTTPException(status_code=404, detail=f'Rule {update.rule_id} not found')

    # Safeguard -- prevent disabling all rules simultaneously
    if update.enabled is False:
        enabled_count = sum(1 for r in rules if r.get('enabled', False))
        if enabled_count == 0:
            # Revert the change
            for rule in rules:
                if rule.get('id') == update.rule_id:
                    rule['enabled'] = True
                    break
            raise HTTPException(
                status_code=409,
                detail='Cannot disable all policy rules simultaneously -- at least one rule must remain enabled'
            )
    save_policy(policy)
    logging.info(f'Policy rule {update.rule_id} set enabled={update.enabled} by {current_user["username"]}')
    return {'status': 'ok', 'rule_id': update.rule_id, 'enabled': update.enabled}

# ── Entry point ───────────────────────────────────────────────────────
if __name__ == '__main__':
    import uvicorn
    uvicorn.run(
        'api:app',
        host='0.0.0.0',
        port=8443,
        ssl_keyfile=KEY_FILE,
        ssl_certfile=CERT_FILE,
        server_header=False,
        log_level='info',
        app_dir=os.path.dirname(os.path.abspath(__file__)),
    )
