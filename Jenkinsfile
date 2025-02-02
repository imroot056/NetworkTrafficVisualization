pipeline {
    agent none

    environment {
        REPO_NAME = 'ghcr.io/imroot056/networktrafficvisualization/my-net-mon'
        IMAGE_TAG = "v1.${BUILD_NUMBER}"
    }

    stages {
        // Stage 0: Pull the latest repository updates
        stage('Git Pull on Both Nodes') {
            parallel {
                stage('Git Pull on my-net-mon') {
                    agent { label 'my-net-mon' }
                    steps {
                        echo 'Performing git pull on my-net-mon...'
                        script {
                            dir('/home/ubuntu/NetworkTrafficVisualization') {
                                sh 'git pull'
                            }
                        }
                    }
                }
                stage('Git Pull on visualization-server') {
                    agent { label 'visualization-server' }
                    steps {
                        echo 'Performing git pull on visualization-server...'
                        script {
                            dir('/home/ubuntu/NetworkTrafficVisualization') {
                                sh 'git pull'
                            }
                        }
                    }
                }
            }
        }

        // Stage 1: Build Docker Image on my-net-mon
        stage('Build Docker Image') {
            agent { label 'my-net-mon' }
            steps {
                echo 'Building Docker image on my-net-mon...'
                script {
                    try {
                        // Build the Docker image
                        sh """
                        docker build -t ${REPO_NAME}:${IMAGE_TAG} /home/ubuntu/NetworkTrafficVisualization/Dockerfile
                        """

                        // Push the Docker image
                        echo 'Pushing Docker image to Docker Container Registry...'
                        sh """
                        docker push ${REPO_NAME}:${IMAGE_TAG}
                        """
                    } catch (Exception e) {
                        error "Failed during Build Docker Image: ${e.message}"
                    }
                }
            }
        }

        // Stage 2: Run on visualization-server
        stage('Run on visualization-server') {
            agent { label 'visualization-server' }
            steps {
                echo 'Starting Docker Compose on visualization-server...'
                script {
                    try {
                        dir('/home/ubuntu/NetworkTrafficVisualization/docker-compose/visualization-server') {
                            sh 'docker compose -f docker-compose.yml up -d'
                        }
                    } catch (Exception e) {
                        error "Failed to start Docker Compose on visualization-server: ${e.message}"
                    }
                }
            }
        }

        // Stage 3: Run on my-net-mon
        stage('Run on my-net-mon') {
            agent { label 'my-net-mon' }
            steps {
                echo 'Starting Docker Compose on my-net-mon...'
                script {
                    try {
                        dir('/home/ubuntu/NetworkTrafficVisualization/docker-compose/my-net-mon') {
                            sh 'docker compose -f docker-compose.yml up -d'
                        }
                    } catch (Exception e) {
                        error "Failed to start Docker Compose on my-net-mon: ${e.message}"
                    }
                }
            }
        }

        // Stage 4: Clean Up Old Docker Images
        stage('Clean Up Old Docker Images') {
            agent { label 'my-net-mon' }
            steps {
                echo 'Cleaning up old Docker images...'
                script {
                    try {
                        sh """
                        echo 'Removing dangling Docker images...'
                        docker image prune -af
                        echo 'Cleaning images older than 7 days...'
                        docker images | grep '<none>' | awk '{print \$3}' | xargs -r docker rmi
                        """
                    } catch (Exception e) {
                        error "Failed during Docker Image Cleanup: ${e.message}"
                    }
                }
            }
        }
    }

    post {
        success {
            echo 'Pipeline succeeded.'
            mail to: 'imroot056@gmail.com', 
                subject: "Build Success: ${env.JOB_NAME} #${env.BUILD_NUMBER}", 
                body: """
                Hello,

                The Jenkins pipeline build has successfully completed.

                Details:
                - Job Name: ${env.JOB_NAME}
                - Build Number: ${env.BUILD_NUMBER}
                - Repository: ${REPO_NAME}
                - Image Tag: ${IMAGE_TAG}
                - Duration: ${currentBuild.durationString}

                Logs and details can be accessed at: ${env.BUILD_URL}

                Best regards,
                Jenkins
                """
        }
        failure {
            echo 'Pipeline failed.'
            mail to: 'imroot056@gmail.com', 
                subject: "Build Failure: ${env.JOB_NAME} #${env.BUILD_NUMBER}", 
                body: """
                Hello,

                The Jenkins pipeline build has failed.

                Details:
                - Job Name: ${env.JOB_NAME}
                - Build Number: ${env.BUILD_NUMBER}
                - Repository: ${REPO_NAME}
                - Image Tag: ${IMAGE_TAG}
                - Duration: ${currentBuild.durationString}

                Logs and failure details can be accessed at: ${env.BUILD_URL}

                Please check the logs and fix the issue.

                Best regards,
                Jenkins
                """
        }
    }
}
