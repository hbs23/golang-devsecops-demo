pipeline {
  agent any

  environment {
    APP_NAME = "go-praktikum-api"
    IMAGE_TAG = "${APP_NAME}:${env.BUILD_NUMBER}"
    APP_PORT = "8090"
    CODEQL_VERSION = "v2.18.4" // contoh; sesuaikan
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Build (Docker)') {
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
                apk add --no-cache git ca-certificates >/dev/null &&
                go version &&
                [ -f go.mod ] || go mod init github.com/example/golang-banking-gin-alpine &&
                go mod tidy || true &&
                echo '🔎 Cari paket Go...' &&
                PKGS=\$(go list ./... 2>/dev/null || true) &&
                if [ -z \"\$PKGS\" ]; then
                echo 'ℹ️  Tidak ada paket Go ditemukan. Lewati unit test.'; exit 0;
                else
                echo '📦 Paket:'; echo \"\$PKGS\" | tr ' ' '\n';
                echo '🚀 Jalankan unit test...';
                go test -v -count=1 -race -coverprofile=coverage.out \$PKGS;
                fi
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
            mkdir -p reports
            docker run --rm -v $PWD:/src -w /src returntocorp/semgrep:latest \
                semgrep --config p/owasp-top-ten --config p/golang \
                --error --json --output reports/semgrep.json .
            '''
        }
        post {
            always {
            archiveArtifacts artifacts: 'reports/semgrep.json', allowEmptyArchive: true
            }
        }
    }

    stage('SAST - CodeQL (Go)') {
        steps {
            sh '''
            mkdir -p reports codeql-db-go .codeql-packs

            # Buat database (install Go sekali di container)
            docker run --rm \
                -v $PWD:/src -w /src \
                -v $PWD/codeql-db-go:/db \
                -v $PWD/.codeql-packs:/root/.codeql/packages \
                ghcr.io/github/codeql/codeql-cli:v2.18.4 \
                bash -lc "apt-get update && apt-get install -y golang git >/dev/null && \
                        codeql database create /db --language=go --source-root /src --command=\\"go build ./...\\""

            # Download packs (cached)
            docker run --rm \
                -v $PWD/.codeql-packs:/root/.codeql/packages \
                ghcr.io/github/codeql/codeql-cli:v2.18.4 \
                codeql pack download codeql/go-queries

            # Analyze with security-extended suite (SARIF 2.1.0)
            docker run --rm \
                -v $PWD/codeql-db-go:/db \
                -v $PWD/reports:/out \
                -v $PWD/.codeql-packs:/root/.codeql/packages \
                ghcr.io/github/codeql/codeql-cli:v2.18.4 \
                codeql database analyze /db \
                codeql/go-queries:codeql-suites/go-security-extended.qls \
                --format=sarifv2.1.0 --output=/out/codeql.sarif --threads=0 || true
            '''
        }
        post {
            always {
            archiveArtifacts artifacts: 'reports/codeql.sarif', allowEmptyArchive: true
            }
        }
    }

    stage('SCA - Trivy (Repo deps)') {
      steps {
        sh """
          docker run --rm -v \$PWD:/work -w /work aquasec/trivy:latest \
            fs --security-checks vuln --severity CRITICAL,HIGH \
            --format sarif --output trivy-fs.sarif .
        """
      }
      post {
        always {
          archiveArtifacts artifacts: 'trivy-fs.sarif', onlyIfSuccessful: false
        }
      }
    }

    stage('Build Image (Release)') {
      steps {
        sh "docker build -t ${IMAGE_TAG} ."
      }
    }

    stage('SCA - Trivy (Image)') {
      steps {
        sh """
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy:latest image --severity CRITICAL,HIGH \
            --vuln-type os,library --ignore-unfixed \
            --format sarif --output trivy-image.sarif ${IMAGE_TAG}
        """
      }
      post {
        always {
          archiveArtifacts artifacts: 'trivy-image.sarif', onlyIfSuccessful: false
        }
      }
    }

    stage('SBOM - Trivy (CycloneDX)') {
      steps {
        sh """
          docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy:latest sbom --format cyclonedx \
            --output sbom.cdx.json ${IMAGE_TAG}
        """
      }
      post {
        always {
          archiveArtifacts artifacts: 'sbom.cdx.json', onlyIfSuccessful: false
        }
      }
    }

    stage('Run App for DAST') {
      steps {
        sh """
          # Jalankan container app di background untuk DAST
          docker run -d --rm --name ${APP_NAME} -p ${APP_PORT}:${APP_PORT} ${IMAGE_TAG}
          # Health check sederhana (tunggu app ready)
          for i in \$(seq 1 30); do
            curl -sf http://localhost:${APP_PORT}/health && break
            sleep 2
          done
        """
      }
    }

    stage('DAST - OWASP ZAP (Baseline)') {
      steps {
        sh """
          docker run --rm -v \$PWD:/zap/wrk/:rw --network="host" \
            ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
            -t http://localhost:${APP_PORT} \
            -r zap-baseline.html -J zap-baseline.json || true
        """
      }
      post {
        always {
          archiveArtifacts artifacts: 'zap-baseline.*', onlyIfSuccessful: false
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