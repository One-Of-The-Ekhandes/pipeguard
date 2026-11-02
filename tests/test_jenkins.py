from helpers import findings, ids

GOOD = """
pipeline {
  agent { label 'linux-build' }
  options { timeout(time: 30, unit: 'MINUTES') }
  stages {
    stage('Deploy') {
      steps {
        withCredentials([usernamePassword(credentialsId: 'repo', usernameVariable: 'U', passwordVariable: 'P')]) {
          sh 'curl -u "$U:$P" https://repo.example.com/upload'
        }
        input message: 'Deploy to prod?', submitter: 'release-managers'
      }
    }
  }
}
"""


def test_clean_jenkinsfile():
    assert ids("jenkins", GOOD) == []


def test_credential_interpolation_single_and_triple_quotes():
    jf = """
pipeline {
  agent { label 'x' }
  options { timeout(time: 5, unit: 'MINUTES') }
  environment { NEXUS = credentials('nexus') }
  stages { stage('a') { steps {
    withCredentials([string(credentialsId: 't', variable: 'TOKEN')]) {
      sh "curl -H 'Authorization: Bearer ${TOKEN}' https://api"
      sh '''echo $TOKEN is fine'''
      sh \"\"\"
        docker login -u $NEXUS_USR -p $NEXUS_PSW
      \"\"\"
    }
  } } }
}
"""
    fs = [f for f in findings("jenkins", jf) if f.rule.id == "PG-JNK-002"]
    assert [f.line for f in fs] == [7, 10]


def test_hardcoded_secret_and_placeholder():
    jf = "pipeline {\n  agent { label 'x' }\n  options { timeout(time: 5, unit: 'MINUTES') }\n" \
         "  environment {\n    DB_PASSWORD = 'S3cr3t-Pa55'\n    API_TOKEN = 'changeme'\n    REGION = 'eu-west-1'\n  }\n}\n"
    fs = [f for f in findings("jenkins", jf) if f.rule.id == "PG-JNK-003"]
    assert [f.line for f in fs] == [5]


def test_agent_any_timeout_pipe_image_privileged():
    jf = """
pipeline {
  agent any
  stages {
    stage('build') {
      agent { docker { image 'node:latest'; args '-v /var/run/docker.sock:/var/run/docker.sock' } }
      steps { sh 'curl -fsSL https://get.tool.sh | bash' }
    }
  }
}
"""
    assert ids("jenkins", jf) == ["PG-JNK-001", "PG-JNK-004", "PG-JNK-005", "PG-JNK-006", "PG-JNK-007"]


def test_param_injection():
    jf = "node {\n  timeout(5) {\n    sh \"./deploy.sh ${params.ENVIRONMENT}\"\n    sh './deploy.sh \"$ENVIRONMENT\"'\n" \
         "    sh \"git checkout ${env.BRANCH_NAME}\"\n  }\n}\n"
    fs = [f for f in findings("jenkins", jf) if f.rule.id == "PG-JNK-008"]
    assert [f.line for f in fs] == [3, 5]


def test_input_without_submitter_and_dynamic_code():
    jf = "@Grab('org.yaml:snakeyaml:2.2')\nnode {\n  timeout(5) {\n    input message: 'Ship it?'\n" \
         "    evaluate(readFile('extra.groovy'))\n  }\n}\n"
    assert ids("jenkins", jf) == ["PG-JNK-009", "PG-JNK-010", "PG-JNK-010"]
