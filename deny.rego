package docker_hub_image_pull_secrets

import rego.v1

deny_docker_hub_without_image_pull_secrets contains msg if {
	is_workload(input.kind)
	not has_image_pull_secrets(input.spec.template.spec)

	some container in input.spec.template.spec.containers
	is_docker_hub_image(container.image)

	msg = sprintf("%s/%s: imagePullSecrets is required for Docker Hub image %s", [
		input.kind,
		input.metadata.name,
		container.image,
	])
}

deny_unnecessary_image_pull_secrets contains msg if {
	is_workload(input.kind)
	has_image_pull_secrets(input.spec.template.spec)
	not has_docker_hub_image(input.spec.template.spec.containers)

	msg = sprintf("%s/%s: imagePullSecrets is not required for non Docker Hub image", [
		input.kind,
		input.metadata.name,
	])
}

has_image_pull_secrets(pod_spec) if {
	count(pod_spec.imagePullSecrets) > 0
}

is_workload(kind) if {
	some workload_kind in [
		"Deployment",
		"Job",
		"StatefulSet",
		"DaemonSet",
	]
	kind == workload_kind
}

has_docker_hub_image(containers) if {
	some container in containers
	is_docker_hub_image(container.image)
}

is_docker_hub_image(image) if {
	# repository name only contain lowercase letters, numbers, hyphens (-), and underscores (_)
	# https://docs.docker.com/docker-hub/repos/
	some docker_hub_image_pattern in [
		"^[a-z0-9_-]+/[a-z0-9_-]+:",
		"^[a-z0-9_-]+:",
	]
	regex.match(docker_hub_image_pattern, image)
}
