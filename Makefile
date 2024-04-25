KIND_CLUSTER_NAME ?= veth-ethtool
MAKEFILE_DIR = $(shell cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd)
OUTPUT_DIR = $(MAKEFILE_DIR)/_output
KIND_CLUSTER_CONFIG ?= $(OUTPUT_DIR)/kubeconfig
CONTAINER_IMAGE ?= quay.io/akaris/veth-ethtool:latest
SAVED_IMAGE ?= $(OUTPUT_DIR)/image.tar

.PHONY: build
build:
	go build -o _output/veth-ethtool

.PHONY: test
test:
	go test -v -count 1 ./...

.PHONY: test-coverage
test-coverage:
	go test -v -coverprofile=$(OUTPUT_DIR)/cover.out -count 1 ./...
	go tool cover -html=$(OUTPUT_DIR)/cover.out

.PHONY: build-container
build-container:
	podman build -t $(CONTAINER_IMAGE) .

.PHONY: load-container-image-kind
load-container-image-kind:
	podman save $(CONTAINER_IMAGE) > $(SAVED_IMAGE)
	KIND_EXPERIMENTAL_PROVIDER=podman kind load image-archive $(SAVED_IMAGE) --name $(KIND_CLUSTER_NAME)
	rm -f $(SAVED_IMAGE)

.PHONY: deploy-kubernetes
deploy-kubernetes:
	kubectl kustomize $(MAKEFILE_DIR)/config/kubernetes | kubectl apply -f -

.PHONY: undeploy-kubernetes
undeploy-kubernetes:
	kubectl kustomize $(MAKEFILE_DIR)/config/kubernetes | kubectl delete -f -

.PHONY: create-kind
create-kind:
	KIND_EXPERIMENTAL_PROVIDER=podman kind create cluster --name $(KIND_CLUSTER_NAME) --kubeconfig $(KIND_CLUSTER_CONFIG)

.PHONY: destroy-kind
destroy-kind:
	KIND_EXPERIMENTAL_PROVIDER=podman kind delete cluster --name $(KIND_CLUSTER_NAME)

.PHONY: e2e-test
e2e-test: build-container load-container-image-kind
	export KUBECONFIG=$(KIND_CLUSTER_CONFIG) && \
	cd $(MAKEFILE_DIR)/e2e && \
	go test -v -count 1 ./...
