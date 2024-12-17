pipeline {
    agent any

    stages {
        // Stage 1: Clean Up
        stage('Clean Up') {
            parallel {
                stage('Clean Up on built-in-node') {
                    agent {
                        label 'built-in-node'
                    }
                    steps {
                        echo 'Cleaning up on built-in-node...'
                        // Remove previous Docker images and containers (ignore errors if they don't exist)
                        sh 'docker rmi -f harbor.registry.local/devops-mynetmon/my-net-mon:v1.$((BUILD_NUMBER - 1)) || true'
                        
                    }
                }
                stage('Clean Up on ubuntu-slave-node') {
                    agent {
                        label 'ubuntu-slave-node'
                    }
                    steps {
                        echo 'Cleaning up on ubuntu-slave-node...'
                        // Remove previous Docker images and containers (ignore errors if they don't exist)
                        sh 'docker rmi -f harbor.registry.local/devops-mynetmon/my-net-mon:v1.$((BUILD_NUMBER - 1)) || true'
                        sh 'docker container stop my-net-mon || true'
                        sh 'docker container rm my-net-mon || true'
                        sh 'docker compose -f ./docker-compose/docker-compose.yml down || true'
                    }
                }
            }
        }

        // Stage 2: Build Docker Image
        stage('Build') {
            agent {
                label 'built-in-node'
            }
            steps {
                echo 'Building Docker image on built-in-node...'
                // Build a new Docker image
                sh 'docker build -t harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER ./my-net-mon-docker-image/'
                echo 'Pushing Docker image...'
                // Push the newly built Docker image to the registry
                sh 'docker push harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER'

            }
        }

        // Stage 3: Deploy Containers
        stage('Deploy') {
            agent {
                label 'ubuntu-slave-node'
            }
            steps {
                echo 'Pulling and Deploying containers...'
                // Pull necessary Docker images
                sh 'docker pull harbor.registry.local/devops-mynetmon/openserach'
                sh 'docker pull harbor.registry.local/devops-mynetmon/openserach-dashboards'
                sh 'docker pull harbor.registry.local/devops-mynetmon/logstash'
                sh 'docker pull harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER'

                // Start Docker containers using Docker Compose
                sh 'docker compose -f ./docker-compose/docker-compose.yml up -d'

                // Run a Docker container with a specific name and volume
                sh 'docker run -itd --name my-net-mon -v /home/nova007/logfiles:/opt/logfiles harbor.registry.local/devops-mynetmon/my-net-mon:v1.$BUILD_NUMBER'
            }
        }
    }

    post {
        always {
            mail to: 'imroot056@gmail.com',
            subject: "Job '${JOB_NAME}' build number #${BUILD_NUMBER} is being built",
            body: "Please go to ${BUILD_URL} and verify the build"
        }
        success {
            mail to: 'imroot056@gmail.com',
            subject: "Job '${JOB_NAME}' build number #${BUILD_NUMBER} is built successfully",
            body: "Please go to ${BUILD_URL} and verify the build. The Net Monitor build is successful. You can open the dashboard on http://localhost:5601."
        }
        failure {
            mail to: 'imroot056@gmail.com',
            subject: "Job '${JOB_NAME}' build number #${BUILD_NUMBER} Failed",
            body: "Please go to ${BUILD_URL} and verify the build"
        }
    }
}
