// Jenkins shared library step: pipeguardScan(path: '.', failOn: 'high')
//
// Install the library under Manage Jenkins > System > Global Pipeline Libraries, then:
//   @Library('pipeguard@v0.1.0') _
//   pipeguardScan(failOn: 'high')
//
// The step installs PipeGuard in a virtual environment, writes SARIF and Markdown reports,
// archives them, and fails the build when findings reach the failOn severity.
// Values are passed through withEnv and read by the shell, never interpolated by Groovy,
// so a crafted path or severity cannot inject shell commands.

def call(Map config = [:]) {
    def allowed = ['info', 'low', 'medium', 'high', 'critical']
    def failOn = (config.failOn ?: 'high').toString().toLowerCase()
    if (!allowed.contains(failOn)) {
        error("pipeguardScan: failOn must be one of ${allowed}")
    }
    def scanPath = (config.path ?: '.').toString()
    def version = (config.version ?: 'v0.1.0').toString()

    withEnv(["PG_PATH=${scanPath}", "PG_FAIL_ON=${failOn}", "PG_VERSION=${version}"]) {
        def status = sh(returnStatus: true, script: '''
            set -eu
            python3 -m venv .pipeguard-venv
            .pipeguard-venv/bin/pip install --quiet "git+https://github.com/One-Of-The-Ekhandes/pipeguard.git@${PG_VERSION}"
            .pipeguard-venv/bin/pipeguard scan "$PG_PATH" --format markdown --output pipeguard-report.md --fail-on "$PG_FAIL_ON" || rc=$?
            .pipeguard-venv/bin/pipeguard scan "$PG_PATH" --format sarif --output pipeguard-report.sarif --fail-on critical >/dev/null || true
            exit ${rc:-0}
        ''')
        archiveArtifacts artifacts: 'pipeguard-report.*', allowEmptyArchive: true
        if (status != 0) {
            error("PipeGuard found issues at or above '${failOn}' severity. See pipeguard-report.md.")
        }
    }
}
