# Golang Banking Security Lab (Gin, Go 1.24-alpine)

> Simulasi API perbankan **sengaja rentan** untuk praktik SAST (Semgrep/CodeQL),
> DAST (OWASP ZAP), dan Vulnerability/SCA (Trivy). **Jangan gunakan di production.**

## Stack
- Go **1.24 (alpine)**, Gin
- MySQL 8
- Docker & docker-compose

## Jalankan
```bash
docker compose up -d --build
curl http://localhost:8080/ping
```

## Endpoint Banking (sengaja vuln)
- `POST /auth/login` → JWT dengan **hardcoded secret**
- `GET /me/balance` → abaikan klaim JWT (fixed user=1)
- `POST /transfer` → **IDOR**, **float money**, **OTP bypass** (`0000`)
- `GET /accounts/:id` → **IDOR**
- `GET /admin/export-logs` → **tanpa auth**

## Endpoint Lain
- `GET /hash?data=x` → **MD5**
- `POST /encrypt` (data) → **CBC zero IV**
- `POST /exec?cmd=...` → **Command injection**
- `POST /upload` → **Path traversal**
- `GET /redirect?url=...` → **Open redirect**
- `GET /secret` → **Env leak**

## SAST – Semgrep
```bash
pip install semgrep
semgrep --config semgrep-rules.yml .
# Tambahan ruleset resmi:
semgrep --config p/ci --config p/golang .
```

## SAST – CodeQL (opsional)
```bash
codeql database create db-go --language=go --source-root .
codeql database analyze db-go --format=sarifv2 --output=codeql.sarif --download --   github/codeql/go/qlpack@latest --ram=4096
```

## SCA/Vulnerability – Trivy
```bash
# Source + license + secrets
trivy fs --scanners vuln,license,secret .

# Image
docker build -t banking-gin:local .
trivy image --severity HIGH,CRITICAL banking-gin:local
```

## DAST – OWASP ZAP
```bash
docker run --rm -t -v "$PWD:/zap/wrk" owasp/zap2docker-stable   zap-baseline.py -t http://host.docker.internal:8080 -r zap_report.html
```

## Catatan
Proyek ini berisi **vulnerability yang disengaja** untuk tujuan edukasi (SQLi/IDOR/crypto/command injection/redirect/CSRF-ish).
