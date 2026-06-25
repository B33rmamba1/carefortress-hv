# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in CareFortress, please report it responsibly by emailing smithjamesd89@live.com. Do not open a public issue.

## Known Disclosures

### Compromised TLS Keys in Git History

**Status:** Rotated. Old keys are no longer in use.

The following private keys were committed to the repository in early development and subsequently removed in commit `643cc3b`. The keys remain recoverable from git history.

- `certs/ca.key` - Internal CA private key
- `certs/medical-vm.key` - Medical VM TLS key
- `certs/mgmt-vm.key` - Management VM TLS key
- `certs/audit-vm.key` - Audit VM TLS key

**All keys were rotated on June 25, 2026.** The keys in git history are compromised and must not be trusted. Any certificate signed by the old CA (SHA1 fingerprint containing `3ae6f54f` MD5) should be rejected.

Current certificates use a new CA generated post-rotation. The new CA private key has never been committed to the repository.

### Bcrypt Password Hash in Git History

A bcrypt password hash for the API admin user was committed in early development and subsequently replaced in commit `18e2a20`. The exposed hash (`$2b$12$eFOleOz5...`) is no longer valid. The API password was rotated before the repository was made public.

## Key Management

- TLS private keys are excluded from git via `.gitignore`
- The HMAC agent key (`/etc/carefortress-agent.key`) is never committed to the repository
- API credentials are never committed to the repository
- All commits are GPG signed (key `0F882789E2917D31199070ED192C47200722413B`)
