package docker_hub_image_pull_secrets

import rego.v1

# GHCR
deployment_ghcr_without_image_pull_secrets := yaml.unmarshal(`
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      containers:
        - image: ghcr.io/foo/bar:v1.2.3
`)

test_deployment_ghcr_without_image_pull_secrets if {
	got := deny_docker_hub_without_image_pull_secrets with input as deployment_ghcr_without_image_pull_secrets
	count(got) == 0
}

deployment_ghcr_with_empty_image_pull_secrets := yaml.unmarshal(`
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      imagePullSecrets: []
      containers:
        - image: ghcr.io/foo/bar:v1.2.3
`)

test_deployment_ghcr_without_image_pull_secrets if {
	got := deny_docker_hub_without_image_pull_secrets with input as deployment_ghcr_with_empty_image_pull_secrets
	count(got) == 0
}

deployment_ghcr_with_image_pull_secrets := yaml.unmarshal(`
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      imagePullSecrets:
        - name: docker-hub
      containers:
        - image: ghcr.io/foo/bar:v1.2.3
`)

test_deployment_ghcr_with_image_pull_secrets if {
	got := deny_unnecessary_image_pull_secrets with input as deployment_ghcr_with_image_pull_secrets
	count(got) == 1
}
