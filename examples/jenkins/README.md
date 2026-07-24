# Jenkins CI/CD

Use Foxhole as a pipeline stage: update (or reuse) the local vuln DB, scan the
workspace, archive reports, and fail the build on policy exit code **2**.

No Jenkins plugin is required — only Docker (or a binary on the agent).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Pass (or no policy configured) |
| `1` | Runtime / usage error |
| `2` | Policy gate failed — fail the stage |

## Declarative pipeline (Docker)

Copy [Jenkinsfile](Jenkinsfile) into your app repo (or load it as a shared
library). Commit a policy file such as [../policy.yaml](../policy.yaml) as
`foxhole-policy.yaml` at the repo root.

```groovy
pipeline {
  agent any
  environment {
    FOXHOLE_IMAGE = 'ghcr.io/jasonflaherty/foxhole:latest'
    FOXHOLE_DB_PATH = "${WORKSPACE}/.foxhole/foxhole.db"
  }
  stages {
    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Foxhole DB update') {
      steps {
        sh '''
          mkdir -p "$(dirname "$FOXHOLE_DB_PATH")"
          docker run --rm \
            -v "$WORKSPACE:/work" \
            -e FOXHOLE_DB_PATH=/work/.foxhole/foxhole.db \
            -e FOXHOLE_NVD_API_KEY \
            "$FOXHOLE_IMAGE" db update /work
        '''
      }
    }

    stage('Foxhole scan') {
      steps {
        sh '''
          docker run --rm \
            -v "$WORKSPACE:/work" \
            -e FOXHOLE_DB_PATH=/work/.foxhole/foxhole.db \
            -w /work \
            "$FOXHOLE_IMAGE" /work \
              --report console,json,sarif,html \
              --policy /work/foxhole-policy.yaml \
              --fail-on high
        '''
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: 'foxhole-report.*', allowEmptyArchive: true
    }
  }
}
```

### Docker agent alternative

```groovy
agent {
  docker {
    image 'ghcr.io/jasonflaherty/foxhole:latest'
    args '-v $HOME/.foxhole:/var/lib/foxhole'
  }
}
steps {
  sh 'foxhole db update .'
  sh 'foxhole . --fail-on high --report console,json,sarif'
}
```

## Patterns

1. **Shared DB** — Persist `.foxhole/foxhole.db` on the agent or a named volume so PR jobs can run with `--offline` after a nightly `db update`.
2. **Offline PRs** — Warm the DB in a scheduled job; PR pipelines use `--offline` to avoid NVD/OSV network calls.
3. **Credentials** — Store `FOXHOLE_NVD_API_KEY`, `FOXHOLE_TEAMS_WEBHOOK`, SMTP vars in Jenkins credentials and inject as env.
4. **Notify** — Add `--teams` / `--email` / `--github` on the scan stage when those env vars are set.
5. **HTML report** — Optional [HTML Publisher](https://plugins.jenkins.io/htmlpublisher/) on `foxhole-report.html`.
6. **GHCR auth** — If the package is private: `docker login ghcr.io` on the agent (or pull mirror).

## Without Docker

Install the CLI on the agent (`go install github.com/jasonflaherty/foxhole/cmd/foxhole@latest` or a release binary), then:

```bash
foxhole db update
foxhole . --policy foxhole-policy.yaml --report console,json,sarif
```

## Related

- Policy example: [../policy.yaml](../policy.yaml)
- Container pull: [../../docker/README.md](../../docker/README.md)
- Exit codes / flags: [../../README.md](../../README.md)
