package main

test_allow_docker_hub_with_image_pull_secrets {
	resourceYAML := `
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
`
	resource := yaml.unmarshal(resourceYAML)
	got := deny_docker_hub_without_image_pull_secrets with input as resource
    count(got) == 0
}

test_deny_docker_hub_without_image_pull_secrets {
	resourceYAML := `
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      containers:
        - image: nginx:latest
`
	resource := yaml.unmarshal(resourceYAML)
	got := deny_docker_hub_without_image_pull_secrets with input as resource
    count(got) == 1
}

test_deny_mixed_docker_hub_without_image_pull_secrets {
	resourceYAML := `
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      containers:
        - image: ghcr.io/foo/bar:v1.2.3
        - image: envoyproxy/envoy:latest
`
	resource := yaml.unmarshal(resourceYAML)
	got := deny_docker_hub_without_image_pull_secrets with input as resource
	count(got) == 1
}

test_allow_ghcr_with_empty_image_pull_secrets {
	resourceYAML := `
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      imagePullSecrets: []
      containers:
        - image: ghcr.io/foo/bar:v1.2.3
`
	resource := yaml.unmarshal(resourceYAML)
	got := deny_docker_hub_with_empty_image_pull_secrets with input as resource
	count(got) == 0
}

test_deny_docker_hub_with_empty_image_pull_secrets {
	resourceYAML := `
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      imagePullSecrets: []
      containers:
        - image: nginx:latest
`
	resource := yaml.unmarshal(resourceYAML)
	got := deny_docker_hub_with_empty_image_pull_secrets with input as resource
	count(got) == 1
}

test_allow_necessary_image_pull_secrets {
	resourceYAML := `
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
`
	resource := yaml.unmarshal(resourceYAML)
	got := deny_unnecessary_image_pull_secrets with input as resource
	count(got) == 0
}

test_allow_necessary_image_pull_secrets_mixed {
	resourceYAML := `
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      imagePullSecrets:
        - docker-hub
      containers:
        - image: ghcr.io/foo/bar:v1.2.3
        - image: nginx:latest
`
	resource := yaml.unmarshal(resourceYAML)
	got := deny_unnecessary_image_pull_secrets with input as resource
	count(got) == 0
}

test_deny_unnecessary_image_pull_secrets {
	resourceYAML := `
kind: Deployment
metadata:
  name: fixture
spec:
  template:
    spec:
      imagePullSecrets:
        - docker-hub
      containers:
        - image: ghcr.io/foo/bar:v1.2.3
`
	resource := yaml.unmarshal(resourceYAML)
	got := deny_unnecessary_image_pull_secrets with input as resource
	count(got) == 1
}
