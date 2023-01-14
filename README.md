# conftest-docker-hub-image-pull-secrets [![conftest](https://github.com/int128/conftest-docker-hub-image-pull-secrets/actions/workflows/conftest.yaml/badge.svg)](https://github.com/int128/conftest-docker-hub-image-pull-secrets/actions/workflows/conftest.yaml)

This is a Conftest policy to test `imagePullSecrets` of Kubernetes for Docker Hub images.

- If some container uses an image of Docker Hub, it should have `imagePullSecrets`
- If any container does not use an image of Docker Hub, it should not have `imagePullSecrets`
