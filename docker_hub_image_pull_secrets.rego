package main

workload_kinds := [
	"Deployment",
	"Job",
	"StatefulSet",
	"DaemonSet",
]

deny_docker_hub_image_pull_secret_is_not_set[msg] {
	input.kind == workload_kinds[_]

	image := input.spec.template.spec.containers[_].image
	is_docker_hub_image(image)
	not input.spec.template.spec.imagePullSecrets

	msg = sprintf("%s/%s: set imagePullSecrets for Docker Hub image %s", [
		input.kind,
		input.metadata.name,
		image,
	])
}

deny_docker_hub_image_pull_secret_is_empty[msg] {
	input.kind == workload_kinds[_]

	image := input.spec.template.spec.containers[_].image
	is_docker_hub_image(image)
	count(input.spec.template.spec.imagePullSecrets) == 0

	msg = sprintf("%s/%s: set imagePullSecrets for Docker Hub image %s", [
		input.kind,
		input.metadata.name,
		image,
	])
}

deny_docker_hub_image_pull_secret_is_not_needed[msg] {
	input.kind == workload_kinds[_]

	image := input.spec.template.spec.containers[_].image
	not is_docker_hub_image(image)
	count(input.spec.template.spec.imagePullSecrets) > 0

	msg = sprintf("%s/%s: imagePullSecrets is not needed for image", [
		input.kind,
		input.metadata.name,
	])
}

is_docker_hub_image(image) {
	# repository name only contain lowercase letters, numbers, hyphens (-), and underscores (_)
	# https://docs.docker.com/docker-hub/repos/
	docker_hub_image_patterns = [
		"^[a-z0-9_-]+/[a-z0-9_-]+:",
		"^[a-z0-9_-]+:",
	]
	regex.match(docker_hub_image_patterns[_], image)
}
