pipeline {
  agent any

  environment {
    APP_NAME  = "go-praktikum-api"
    IMAGE_TAG = "${APP_NAME}:${env.BUILD_NUMBER}"
    APP_PORT  = "9000"
  }

  stages {
    stage('Prep workspace') {
        steps {
            sh '''
            echo "🧹 Cleaning workspace..."
            sudo rm -rf reports .trivycache || true
            chmod -R u+rwX . || true
            '''
            deleteDir()
        }
    }

    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Build Image') {
      steps {
        sh '''
          set -e
          docker build --label commit=${GIT_COMMIT} --label build=${BUILD_NUMBER} -t ${IMAGE_TAG} .
        '''
      }
    }

    stage('Unit Test (Go)') {
        steps {
            sh '''
            docker run --rm -v "$PWD":/work -w /work golang:1.22-alpine sh -c "
                set -e
                apk add --no-cache git ca-certificates build-base >/dev/null
                go version
                [ -f go.mod ] || go mod init github.com/example/golang-banking-gin-alpine
                go mod tidy || true
                PKGS=$(go list ./... 2>/dev/null || true)
                if [ -z \\"$PKGS\\" ]; then
                echo 'No Go packages found. Skipping tests.'; exit 0
                fi
                go test -v -count=1 -race -coverprofile=coverage.out $PKGS
            "
            '''
        }
        post {
            always {
            script {
                if (fileExists('coverage.out')) {
                archiveArtifacts artifacts: 'coverage.out', fingerprint: true
                } else {
                echo 'No coverage.out generated.'
                }
            }
            }
        }
    }

   stage('SAST - Semgrep (Blocking)') {
        steps {
            sh '''
        set -e
        echo "== [SAST] Mulai Semgrep scan =="
        mkdir -p reports
        chmod 777 reports || true

        echo "== [SAST] Kirim snapshot via pipe =="
        # jalankan semgrep dalam container; tangkap exit code
        tar \
        --exclude='./reports' \
        --exclude='./.trivycache' \
        --exclude='./node_modules' \
        --exclude='./.git' \
        --warning=no-file-changed \
        -czf - . \
        | docker run --rm -i \
            -v "$WORKSPACE/reports":/out \
            returntocorp/semgrep:latest sh -lc '
            set -e
            mkdir -p /src
            tar -xzf - -C /src
            echo "--- Go files detected ---"
            find /src -maxdepth 3 -type f -name "*.go" -print || true
            semgrep \
                --config p/golang \
                --config p/security-audit \
                --config p/owasp-top-ten \
                --exclude "/src/reports/**" \
                --exclude "/src/.trivycache/**" \
                --exclude "/src/node_modules/**" \
                --json -o /out/semgrep.json /src
            ' || SEMGREP_EXIT=$?

        # If docker/semgrep failed, we still want a semgrep.json fallback so artifact exists
        if [ -z "${SEMGREP_EXIT+x}" ]; then
        SEMGREP_EXIT=0
        fi

        if [ ! -s reports/semgrep.json ]; then
        echo "⚠️ semgrep output missing or empty — buat fallback reports/semgrep.json"
        cat > reports/semgrep.json <<'EOF'
        {
        "errors": ["semgrep failed or produced no output"],
        "results": []
        }
        EOF
        fi

        # parse hasil semgrep dan decide exit code
        python3 - <<'PY'
        import json, sys, os

        p = "reports/semgrep.json"
        if not os.path.exists(p):
            print("❌ [Semgrep] report not found", file=sys.stderr)
            sys.exit(2)

        data = json.load(open(p))
        results = data.get("results", [])
        print(f"🔍 [Semgrep] total findings = {len(results)}")

        # policy: fail if any findings (blocking), or semgrep docker non-zero
        # NOTE: we can change policy: fail only on severity X etc.
        blocking_count = len(results)

        # get semgrep exit propagated via env
        import os
        sem_exit = int(os.environ.get("SEMGREP_EXIT", "0"))
        if sem_exit != 0:
            print(f"❌ semgrep process returned non-zero exit: {sem_exit}", file=sys.stderr)
            # still fail, but artifact exists
            sys.exit(3)

        if blocking_count > 0:
            print("❌ Blocking findings found; failing pipeline as configured.")
            sys.exit(1)

        print("✅ No blocking findings.")
        sys.exit(0)
        PY
        '''
        }
        post {
            always {
            // pastikan archivernya jalan walau step fail
            archiveArtifacts artifacts: 'reports/semgrep.json, reports/semgrep-summary.txt', onlyIfSuccessful: false
            junit allowEmptyResults: true, testResults: 'reports/*.xml' // optional
            }
        }
    }
    // ===== SCA FS (Blocking) =====
    stage('SCA - Trivy (Repo deps) - Blocking') {
        steps {
            sh '''
            set +e
            mkdir -p reports .trivycache
            docker run --rm \
                -v "$PWD":/work -w /work \
                -v "$PWD/.trivycache":/root/.cache/trivy \
                aquasec/trivy:latest fs . \
                --scanners vuln \
                --severity CRITICAL,HIGH \
                --format sarif \
                --exit-code 1 \
                > reports/trivy-fs.sarif
            rc=$?
            echo "[Trivy FS] exit code=$rc"
            set -e
            exit $rc
            '''
        }
        post {
            always {
            archiveArtifacts artifacts: 'reports/trivy-fs.sarif', onlyIfSuccessful: false
            }
        }
    }

    // ===== SCA Image (Blocking) =====
    stage('SCA - Trivy (Image) - Blocking') {
        steps {
            sh '''
            set +e
            mkdir -p reports .trivycache
            docker run --rm \
                -v "$PWD":/work -w /work \
                -v /var/run/docker.sock:/var/run/docker.sock \
                -v "$PWD/.trivycache":/root/.cache/trivy \
                aquasec/trivy:latest image "${IMAGE_TAG}" \
                --severity CRITICAL,HIGH \
                --pkg-types os,library \
                --ignore-unfixed \
                --scanners vuln \
                --format sarif \
                --exit-code 1 \
                --quiet \
                > reports/trivy-image.sarif
            rc=$?
            echo "[Trivy Image] exit code=$rc"
            set -e
            exit $rc
            '''
        }
        post {
            always {
            archiveArtifacts artifacts: 'reports/trivy-image.sarif', onlyIfSuccessful: false
            }
        }
    }

    stage('SBOM - Trivy (CycloneDX)') {
        steps {
            sh '''
            set -e
            mkdir -p reports .trivycache
            docker run --rm \
                -v "$PWD":/work -w /work \
                -v /var/run/docker.sock:/var/run/docker.sock \
                -v "$PWD/.trivycache":/root/.cache/trivy \
                aquasec/trivy:latest image "${IMAGE_TAG}" \
                --format cyclonedx \
                --pkg-types os,library \
                --ignore-unfixed \
                --scanners vuln,license \
                --quiet \
                > reports/sbom.cdx.json
            ls -lah reports || true
            '''
        }
        post {
            always {
            archiveArtifacts artifacts: 'reports/sbom.cdx.json', onlyIfSuccessful: false
            }
        }
    }

    // ===== DAST (Blocking on WARN/FAIL) =====
    stage('Run app & DAST (ZAP Baseline - Blocking)') {
      steps {
        sh '''
          set -e
          docker network inspect ci-net >/dev/null 2>&1 || docker network create ci-net
          docker rm -f ${APP_NAME} >/dev/null 2>&1 || true
          docker run -d --name ${APP_NAME} --network ci-net -p ${APP_PORT}:${APP_PORT} ${IMAGE_TAG}

          ok=0
          for i in $(seq 1 30); do
            if curl -sf http://${APP_NAME}:${APP_PORT}/ping >/dev/null; then echo "App healthy"; ok=1; break; fi
            sleep 2
          done
          if [ "$ok" -ne 1 ]; then
            echo "ERROR: App belum healthy setelah 60 detik" >&2
            docker logs --tail=200 ${APP_NAME} || true
            exit 1
          fi

          mkdir -p reports/zap

          cname=zapscan-$$
          set +e
          docker run --name "$cname" --network ci-net ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py \
              -t http://${APP_NAME}:${APP_PORT} \
              -r zap-baseline.html \
              -J zap-baseline.json \
              -m 5 \
            | tee reports/zap/zap-baseline.txt
          zap_rc=$?
          echo "[ZAP] exit code(baseline)=$zap_rc"
          set -e

          docker cp "$cname":/zap/wrk/. reports/zap/ >/dev/null 2>&1 || true
          docker rm -f "$cname" >/dev/null 2>&1 || true

          [ -s reports/zap/zap-baseline.html ] || cp reports/zap/zap-baseline.txt reports/zap/zap-baseline.html
          [ -s reports/zap/zap-baseline.json ] || echo '{}' > reports/zap/zap-baseline.json

          WARN=$(grep -Eo 'WARN-NEW: *[0-9]+' reports/zap/zap-baseline.txt | awk '{print $2+0}' || echo 0)
          FAIL=$(grep -Eo 'FAIL-NEW: *[0-9]+' reports/zap/zap-baseline.txt | awk '{print $2+0}' || echo 0)
          echo "[ZAP] WARN-NEW=$WARN FAIL-NEW=$FAIL"

          # NOTE: kalau mau FAIL-only, ubah ke: if [ "${FAIL}" -gt 0 ]; then exit 1; fi
          if [ "${FAIL}" -gt 0 ] || [ "${WARN}" -gt 0 ]; then
            echo "[ZAP] Blocking: ditemukan issue WARN/FAIL"; exit 1
          fi

          ls -lah reports/zap || true
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'reports/zap/**', onlyIfSuccessful: false
          sh 'docker rm -f ${APP_NAME} || true'
        }
      }
    }
  }

  post {
    always {
      sh "docker ps -aq --filter 'name=${APP_NAME}' | xargs -r docker stop || true"
    }
  }
}