// Jenkins shared library step: foxholeScan
// Install as a shared library (vars/) or copy into your org library.
//
// foxholeScan(
//   image: 'ghcr.io/jasonflaherty/foxhole:v0.3.0',
//   failOn: 'high',
//   kinds: ['vuln','secret'],
//   requireCosign: false,
//   maxDbAge: '720h',
//   splitReports: true,
//   updateDb: true,
//   policy: 'foxhole-policy.yaml',
//   policyDir: '',
// )

def call(Map args = [:]) {
  def image = args.image ?: (env.FOXHOLE_IMAGE ?: 'ghcr.io/jasonflaherty/foxhole:v0.3.0')
  def failOn = args.failOn ?: 'high'
  def requireCosign = (args.requireCosign ?: false).toString()
  def maxDbAge = args.maxDbAge ?: '720h'
  def splitReports = args.splitReports != false
  def updateDb = args.updateDb != false
  def policy = args.policy ?: 'foxhole-policy.yaml'
  def policyDir = args.policyDir ?: ''
  def kinds = (args.kinds instanceof List) ? args.kinds : []
  def dbPath = args.dbPath ?: "${env.WORKSPACE}/.foxhole/foxhole.db"

  sh """
    set -eu
    docker pull '${image}'
    if [ '${requireCosign}' = 'true' ]; then
      command -v cosign >/dev/null 2>&1 || { echo 'cosign required' >&2; exit 1; }
      cosign verify \
        --certificate-identity-regexp='https://github.com/jasonflaherty/foxhole/\.github/workflows/publish-image\.yml@.*' \
        --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
        '${image}'
    fi
  """

  if (updateDb) {
    sh """
      set -eu
      mkdir -p "\$(dirname '${dbPath}')"
      docker run --rm \\
        -v "\$WORKSPACE:/work" \\
        -e FOXHOLE_DB_PATH=/work/.foxhole/foxhole.db \\
        -e FOXHOLE_NVD_API_KEY \\
        '${image}' db update /work
    """
  }

  def kindFlags = kinds.collect { k -> "--fail-on-kind ${k}" }.join(' ')
  def policyFlag = ""
  if (policy && fileExists(policy)) {
    policyFlag = "--policy /work/${policy}"
  }
  def policyDirFlag = ""
  if (policyDir) {
    policyDirFlag = "--policy-dir /work/${policyDir}"
  }
  def splitFlag = splitReports ? '--split-reports' : ''
  def ageFlag = maxDbAge ? "--max-db-age ${maxDbAge}" : ''
  def evidenceFlag = (args.evidence != false) ? '--evidence' : ''

  sh """
    set -eu
    docker run --rm \\
      -v "\$WORKSPACE:/work" \\
      -e FOXHOLE_DB_PATH=/work/.foxhole/foxhole.db \\
      -e FOXHOLE_IMAGE='${image}' \\
      -w /work \\
      '${image}' /work \\
        --report console,json,sarif,html \\
        --fail-on ${failOn} \\
        ${kindFlags} \\
        ${policyFlag} \\
        ${policyDirFlag} \\
        ${splitFlag} \\
        ${evidenceFlag} \\
        ${ageFlag}
  """

  archiveArtifacts artifacts: 'foxhole-report.*,foxhole-*.json,foxhole-remediation.*,foxhole-evidence/**,foxhole-triage.*', allowEmptyArchive: true
}
