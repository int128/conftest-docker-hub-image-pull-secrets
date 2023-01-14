package main

# Docker Hub
deployment_docker_hub_with_image_pull_secrets := yaml.unmarshal(`
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      imagePullSecrets:
        - docker-hub
      containers:
        - image: nginx:latest
`)

test_deployment_docker_hub_with_image_pull_secrets {
	got := deny_docker_hub_without_image_pull_secrets with input as deployment_docker_hub_with_image_pull_secrets
    count(got) == 0
}

test_deployment_docker_hub_with_image_pull_secrets {
	got := deny_unnecessary_image_pull_secrets with input as deployment_docker_hub_with_image_pull_secrets
    count(got) == 0
}

deployment_docker_hub_without_image_pull_secrets := yaml.unmarshal(`
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      containers:
        - image: nginx:latest
`)

test_deployment_docker_hub_without_image_pull_secrets {
	got := deny_docker_hub_without_image_pull_secrets with input as deployment_docker_hub_without_image_pull_secrets
    count(got) == 1
}

deployment_docker_hub_with_empty_image_pull_secrets := yaml.unmarshal(`
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      imagePullSecrets: []
      containers:
        - image: nginx:latest
`)

test_deployment_docker_hub_with_empty_image_pull_secrets {
	got := deny_docker_hub_without_image_pull_secrets with input as deployment_docker_hub_with_empty_image_pull_secrets
    count(got) == 1
}
