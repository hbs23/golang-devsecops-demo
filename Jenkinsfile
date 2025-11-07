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

    stage('SAST - CodeQL (Security Extended)') {
        steps {
            sh '''
            set -e
            TOOLS=/var/jenkins_home/tools/codeql
            VER=2.18.4
            BUNDLE="$TOOLS/current"                 # folder bundle
            PACKS="$HOME/.codeql/packages"          # cache packs yang diunduh
            SEARCH_PATH="$BUNDLE/qlpacks:$PACKS"    # << kunci: pakai /qlpacks

            mkdir -p "$TOOLS" "$PACKS"
            cd "$TOOLS"

            # Pastikan BUNDLE terpasang
            if [ ! -x "$BUNDLE/codeql" ]; then
                echo "📦 Download CodeQL BUNDLE $VER…"
                curl -L "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${VER}/codeql-bundle-linux64.tar.gz" -o codeql-bundle.tgz
                rm -rf "codeql-${VER}" tmp && mkdir -p tmp
                tar -xzf codeql-bundle.tgz -C tmp
                mv tmp/codeql "codeql-${VER}"
                ln -sfn "codeql-${VER}" current
                rm -rf tmp codeql-bundle.tgz
            else
                echo "✅ CodeQL bundle sudah ada."
            fi

            echo "🔎 Packs terlihat:"
            "$BUNDLE/codeql" resolve qlpacks --search-path="$SEARCH_PATH" || true
            echo "🔎 Languages terlihat:"
            "$BUNDLE/codeql" resolve languages --search-path="$SEARCH_PATH" || true

            cd "$WORKSPACE"
            mkdir -p reports

            # Buat database (build Go via Docker)
            "$BUNDLE/codeql" database create codeql-db-go \
                --overwrite \
                --language=go \
                --source-root . \
                --search-path="$SEARCH_PATH" \
                --command='docker run --rm -v "$PWD":/work -w /work golang:1.22-alpine sh -c "apk add --no-cache git && go build ./..."'

            # (opsional) update query packs publik
            "$BUNDLE/codeql" pack download codeql/go-queries --search-path="$SEARCH_PATH" || true

            # Analyze → SARIF 2.1.0
            "$BUNDLE/codeql" database analyze codeql-db-go \
                codeql/go-queries:codeql-suites/go-security-extended.qls \
                --search-path="$SEARCH_PATH" \
                --format=sarifv2.1.0 --output reports/codeql.sarif --threads=0 || true
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