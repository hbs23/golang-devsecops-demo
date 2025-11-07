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

    // stage('SAST - CodeQL (Security Extended)') {
    //     environment {
    //         TOOLS  = '/var/jenkins_home/tools/codeql'
    //         VER    = '2.18.4'
    //         BUNDLE = "${env.TOOLS}/current"               // CodeQL bundle directory
    //         PACKS  = "${env.HOME}/.codeql/packages"       // Cache untuk packs yg diunduh
    //     }
    //     steps {
    //         withCredentials([string(credentialsId: 'github-secret', variable: 'GITHUB_TOKEN')]) {
    //         sh '''
    //             set -e

    //             # 1) Pastikan CodeQL bundle ada
    //             mkdir -p "$TOOLS" "$PACKS"
    //             if [ ! -x "$BUNDLE/codeql" ]; then
    //             echo "📦 Download CodeQL BUNDLE ${VER}…"
    //             curl -L "https://github.com/github/codeql-action/releases/download/codeql-bundle-v${VER}/codeql-bundle-linux64.tar.gz" -o codeql-bundle.tgz
    //             rm -rf "$TOOLS/codeql-${VER}" tmp && mkdir -p tmp
    //             tar -xzf codeql-bundle.tgz -C tmp
    //             mv tmp/codeql "$TOOLS/codeql-${VER}"
    //             ln -sfn "$TOOLS/codeql-${VER}" "$BUNDLE"
    //             rm -rf tmp codeql-bundle.tgz
    //             else
    //             echo "✅ CodeQL bundle sudah ada."
    //             fi

    //             # Pakai root bundle + cache packs sebagai search-path
    //             SEARCH="$BUNDLE:$PACKS"

    //             # 2) Paksa unduh packs bahasa & query untuk Go
    //             echo "🧹 Bersihkan cache pack Go lama…"
    //             rm -rf "$PACKS"/codeql/go* || true

    //             echo "🔐 Export registry auth untuk GHCR"
    //             export CODEQL_REGISTRY_AUTH='{"https://ghcr.io":{"token":"'"$GITHUB_TOKEN"'"}}'

    //             echo "⬇️  Download pack bahasa (extractor) Go: codeql/go-all"
    //             "$BUNDLE/codeql" pack download codeql/go-all --search-path="$SEARCH" --verbosity=progress+++

    //             echo "⬇️  Download pack queries Go: codeql/go-queries"
    //             "$BUNDLE/codeql" pack download codeql/go-queries --search-path="$SEARCH" --verbosity=progress+++

    //             echo "🔎 Packs terbaca (filter go*):"
    //             "$BUNDLE/codeql" resolve qlpacks --search-path="$SEARCH" | grep -E '^codeql/go(-all|-queries) ' || true

    //             echo "🔎 Languages terbaca (harus ada 'go'):"
    //             "$BUNDLE/codeql" resolve languages --search-path="$SEARCH"

    //             # 3) Build CodeQL DB (pakai container golang agar build reproducible)
    //             cd "$WORKSPACE"
    //             mkdir -p reports

    //             "$BUNDLE/codeql" database create codeql-db-go \
    //             --overwrite \
    //             --language=go \
    //             --source-root . \
    //             --search-path="$SEARCH" \
    //             --command='docker run --rm -v "$PWD":/work -w /work golang:1.22-alpine sh -c "apk add --no-cache git && go build ./..."'

    //             # 4) Analyze → SARIF 2.1.0
    //             "$BUNDLE/codeql" database analyze codeql-db-go \
    //             codeql/go-queries:codeql-suites/go-security-extended.qls \
    //             --search-path="$SEARCH" \
    //             --format=sarifv2.1.0 \
    //             --output reports/codeql.sarif \
    //             --threads=0 || true
    //         '''
    //         }
    //     }
    //     post {
    //         always {
    //         archiveArtifacts artifacts: 'reports/codeql.sarif', allowEmptyArchive: true
    //         }
    //     }
    // }

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
            sh '''
                set -e
                mkdir -p reports .trivycache

                docker run --rm \
                    -v "$PWD":/work -w /work \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    -v "$PWD/.trivycache":/root/.cache/trivy \
                    aquasec/trivy:latest image "go-praktikum-api:31" \
                    --severity CRITICAL,HIGH \
                    --pkg-types os,library \
                    --ignore-unfixed \
                    --scanners vuln \
                    --exit-code 0 \
                    --format sarif \
                    --quiet \
                    > reports/trivy-image.sarif

                echo "Isi folder reports:"
                ls -lah reports || true
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
                aquasec/trivy:latest sbom \
                --image "$IMAGE_TAG" \
                --format cyclonedx \
                --scanners vuln \
                --output /work/reports/sbom.cdx.json

            echo "Isi folder reports:"
            ls -lah reports || true
            '''
        }
        post {
            always {
            archiveArtifacts artifacts: 'reports/sbom.cdx.json', allowEmptyArchive: false
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