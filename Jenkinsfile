pipeline {
  agent any

  environment {
    APP_NAME  = "go-praktikum-api"
    IMAGE_TAG = "${APP_NAME}:${env.BUILD_NUMBER}"
    APP_PORT  = "9000"
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Build Image') {
      steps {
        sh """
          docker build -t ${IMAGE_TAG} .
        """
      }
    }

    stage('Unit Test (Go)') {
      steps {
        sh '''
          docker run --rm -v $PWD:/work -w /work golang:1.22-alpine sh -c "
            set -e
            apk add --no-cache git ca-certificates >/dev/null
            go version
            [ -f go.mod ] || go mod init github.com/example/golang-banking-gin-alpine
            go mod tidy || true

            echo '🔎 Cari paket Go...'
            PKGS=\$(go list ./... 2>/dev/null || true)

            if [ -z \"\$PKGS\" ]; then
              echo 'ℹ️  Tidak ada paket Go ditemukan. Lewati unit test.'
              exit 0
            fi

            echo '📦 Paket:'
            echo \"\$PKGS\" | tr ' ' '\\n'

            echo '🚀 Jalankan unit test...'
            go test -v -count=1 -race -coverprofile=coverage.out \$PKGS
          "
        '''
      }
      post {
        always {
          script {
            if (fileExists('coverage.out')) {
              archiveArtifacts artifacts: 'coverage.out', fingerprint: true
            } else {
              echo 'No coverage.out generated (no Go packages / tests skipped).'
            }
          }
        }
      }
    }

    stage('SAST - Semgrep') {
      steps {
        sh '''
          set -e
          mkdir -p reports
          docker run --rm -v $PWD:/src -w /src returntocorp/semgrep:latest \
            semgrep --config p/owasp-top-ten --config p/golang --config auto \
            --error --json --output reports/semgrep.json .
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'reports/semgrep.json', onlyIfSuccessful: false
        }
      }
    }

    stage('SCA - Trivy (Repo deps)') {
        steps {
            sh '''
            set -e
            mkdir -p reports .trivycache
            docker run --rm \
                -v "$PWD":/work -w /work \
                -v "$PWD/.trivycache":/root/.cache/trivy \
                aquasec/trivy:latest fs . \
                --scanners vuln \
                --severity CRITICAL,HIGH \
                --format sarif \
                > reports/trivy-fs.sarif
            '''
        }
        post {
            always {
            archiveArtifacts artifacts: 'reports/trivy-fs.sarif', onlyIfSuccessful: false
            }
        }
    }

    stage('SCA - Trivy (Image)') {
      steps {
        sh '''
          set -e
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
              --exit-code 0 \
              --format sarif \
              --quiet \
              > reports/trivy-image.sarif

          echo "Isi folder reports:" && ls -lah reports || true
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

          echo "Isi folder reports:" && ls -lah reports || true
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'reports/sbom.cdx.json', onlyIfSuccessful: false
        }
      }
    }

    stage('Run app & DAST') {
        steps {
            sh '''
            set -e

            # 1) Network khusus CI
            docker network inspect ci-net >/dev/null 2>&1 || docker network create ci-net

            # 2) Start app di network yang sama
            docker rm -f go-praktikum-api || true
            docker run -d --name go-praktikum-api --network ci-net -p 9000:9000 go-praktikum-api:46

            # 3) Tunggu health ready (maks 30x, 2 detik)
            ok=0
            for i in $(seq 1 30); do
                if curl -sf http://127.0.0.1:9000/ping >/dev/null; then
                echo "App healthy"
                ok=1
                break
                fi
                sleep 2
            done
            if [ "$ok" -ne 1 ]; then
                echo "ERROR: App belum healthy setelah 60 detik" >&2
                docker logs --tail=200 go-praktikum-api || true
                exit 1
            fi

            # 4) Siapkan folder report
            mkdir -p reports/zap
            chmod 777 reports/zap || true
            rm -f reports/zap/zap.yaml || true

            # 5) Jalankan ZAP di network yang sama, target NAMA container
            docker run --rm \
                --user 0:0 \
                --network ci-net \
                -v "$PWD/reports/zap":/zap/wrk \
                -w /zap/wrk \
                ghcr.io/zaproxy/zaproxy:stable \
                zap-baseline.py \
                -t http://go-praktikum-api:9000 \
                -r zap-baseline.html \
                -J zap-baseline.json \
                -m 5 || true   # batasi durasi baseline 5 menit (opsional)

            echo "Isi reports/zap:"
            ls -lah reports/zap || true
            '''
        }
        post {
            always {
            archiveArtifacts artifacts: 'reports/zap/zap-baseline.*', allowEmptyArchive: true, onlyIfSuccessful: false
            sh 'docker rm -f go-praktikum-api || true'
            }
        }
        }

    stage('DAST - OWASP ZAP (Baseline)') {
      steps {
        sh '''
          set -e
          mkdir -p reports/zap
          chmod 777 reports/zap || true

          docker run --rm \
            --user 0:0 \
            -v "$PWD/reports/zap":/zap/wrk \
            --network=host \
            ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
              -t "http://localhost:${APP_PORT}" \
              -r zap-baseline.html \
              -J zap-baseline.json || true

          echo "Isi reports/zap:" && ls -lah reports/zap || true
        '''
      }
      post {
        always {
          archiveArtifacts artifacts: 'reports/zap/zap-baseline.*', onlyIfSuccessful: false
        }
      }
    }
  }

  post {
    always {
      // Pastikan container app berhenti
      sh "docker ps -aq --filter 'name=${APP_NAME}' | xargs -r docker stop || true"
    }
  }
}