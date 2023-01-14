package main

test_deny_docker_hub_image_pull_secret_is_not_set {
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
	got := deny_docker_hub_image_pull_secret_is_not_set with input as resource
	count(got) == 0
}

test_deny_docker_hub_image_pull_secret_is_not_set {
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
	got := deny_docker_hub_image_pull_secret_is_not_set with input as resource
	count(got) == 1
}

test_deny_docker_hub_image_pull_secret_is_not_set {
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
	got := deny_docker_hub_image_pull_secret_is_not_set with input as resource
	count(got) == 1
}

test_deny_docker_hub_image_pull_secret_is_empty {
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
	got := deny_docker_hub_image_pull_secret_is_empty with input as resource
	count(got) == 0
}

test_deny_docker_hub_image_pull_secret_is_empty {
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
	got := deny_docker_hub_image_pull_secret_is_empty with input as resource
	count(got) == 1
}

test_deny_docker_hub_image_pull_secret_is_not_needed {
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
	got := deny_docker_hub_image_pull_secret_is_not_needed with input as resource
	count(got) == 0
}

test_deny_docker_hub_image_pull_secret_is_not_needed {
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
	got := deny_docker_hub_image_pull_secret_is_not_needed with input as resource
	count(got) == 1
}

test_deny_docker_hub_image_pull_secret_is_not_needed {
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
        - image: quay.io/foo/bar:v1.2.3
`
	resource := yaml.unmarshal(resourceYAML)
	got := deny_docker_hub_image_pull_secret_is_not_needed with input as resource
	count(got) == 1
}
