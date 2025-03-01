package docker_hub_image_pull_secrets

import rego.v1

deny_docker_hub_without_image_pull_secrets contains msg if {
	is_workload(input.kind)
	image := input.spec.template.spec.containers[_].image
	is_docker_hub_image(image)
	not has_image_pull_secrets

	msg = sprintf("%s/%s: imagePullSecrets is required for Docker Hub image %s", [
		input.kind,
		input.metadata.name,
		image,
	])
}

has_image_pull_secrets if {
	count(input.spec.template.spec.imagePullSecrets) > 0
}

deny_unnecessary_image_pull_secrets contains msg if {
	is_workload(input.kind)
	not has_docker_hub_image
	has_image_pull_secrets

	msg = sprintf("%s/%s: imagePullSecrets is not required for non Docker Hub image", [
		input.kind,
		input.metadata.name,
	])
}

has_docker_hub_image if {
	image := input.spec.template.spec.containers[_].image
	is_docker_hub_image(image)
}

is_workload(kind) if {
	workload_kinds := [
		"Deployment",
		"Job",
		"StatefulSet",
		"DaemonSet",
	]
	kind == workload_kinds[_]
}

is_docker_hub_image(image) if {
	# repository name only contain lowercase letters, numbers, hyphens (-), and underscores (_)
	# https://docs.docker.com/docker-hub/repos/
	docker_hub_image_patterns = [
		"^[a-z0-9_-]+/[a-z0-9_-]+:",
		"^[a-z0-9_-]+:",
	]
	regex.match(docker_hub_image_patterns[_], image)
}
