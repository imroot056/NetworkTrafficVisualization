pipeline {
    agent none
    stages {
        stage('Run on visualization-server') {
            agent { label 'visualization-server' }
            steps {
                script {
                    // Navigate to the docker-compose folder and bring up the Docker Compose environment
                    dir('/home/ubuntu/docker-compose') {
                        sh 'docker compose -f docker-compose.yml up -d'
                    }
                }
            }
        }
        
        stage('Run on my-net-mon') {
            agent { label 'my-net-mon' }
            steps {
                script {
                    // Navigate to the docker-compose folder and bring up the Docker Compose environment
                    dir('/home/ubuntu/docker-compose') {
                        sh 'docker compose -f docker-compose.yml up -d'
                    }
                }
            }
        }
    }

    post {
        always {
            echo "Cleaning up after pipeline execution."
        }
        success {
            echo "Docker Compose services started successfully."
        }
        failure {
            echo "There was an issue starting Docker Compose services."
        }
    }
}
