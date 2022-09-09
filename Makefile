#----------------------------------------------------------------------------------
# Versioning
#----------------------------------------------------------------------------------
OUTDIR?=_output
HUB?=ghcr.io/solo-io
REPO_NAME?=bumblebee
EXAMPLES_DIR?=examples
DOCKER := docker

RELEASE := "true"
ifeq ($(TAGGED_VERSION),)
	TAGGED_VERSION := $(shell git describe --tags --dirty --always)
	RELEASE := "false"
endif
# In iron mountain escrow action we pass in the tag as TAGGED_VERSION: ${{ github.ref }}.
# This tag has the refs/tags prefix, which we need to remove here.
export VERSION ?= $(shell echo $(TAGGED_VERSION) | sed -e "s/^refs\/tags\///" | cut -c 2-)

LDFLAGS := -X github.com/solo-io/bumblebee/internal/version.Version=$(VERSION)
GCFLAGS := all="-N -l"

SOURCES := $(shell find . -name "*.go" | grep -v test.go)

.PHONY: clean
clean:
	rm -f $(EXAMPLES_DIR)/**/*.o
	rm -rf $(OUTDIR)


#----------------------------------------------------------------------------------
# Generated Code
#----------------------------------------------------------------------------------
DEPSGOBIN:=$(shell pwd)/.bin
export PATH:=$(DEPSGOBIN):$(PATH)
export GOBIN:=$(DEPSGOBIN)

# Generate go code from protos
.PHONY: generated-code
generated-code:
	go run -ldflags="$(LDFLAGS)" codegen/generate.go
	$(DEPSGOBIN)/goimports -w $(shell ls -d */ | grep -v vendor)

# Go dependencies download
.PHONY: mod-download
mod-download:
	go mod download

# Go tools installation
.PHONY: install-go-tools
install-go-tools: mod-download
	mkdir -p $(DEPSGOBIN)
	go install istio.io/tools/cmd/protoc-gen-jsonshim@1.13.7
	go install github.com/golang/protobuf/protoc-gen-go@v1.4.0
	go install github.com/solo-io/protoc-gen-ext@v0.0.16
	go install github.com/golang/mock/mockgen@v1.5.0
	go install golang.org/x/tools/cmd/goimports@v0.1.2

#----------------------------------------------------------------------------------
# Build Container
#----------------------------------------------------------------------------------
PUSH_CMD:=
PLATFORMS?=linux/amd64
docker-build:
#   may run into issues with apt-get and the apt.llvm.org repo, in which case use --no-cache to build
#   e.g. `docker build --no-cache ./builder -f builder/Dockerfile -t $(HUB)/bumblebee/builder:$(VERSION)
	$(DOCKER) build --platform $(PLATFORMS) $(PUSH_CMD) ./builder -f builder/Dockerfile -t $(HUB)/bumblebee/builder:$(VERSION)

docker-push: PUSH_CMD=--push
docker-push: DOCKER=docker buildx
docker-push: PLATFORMS=linux/amd64,linux/arm64/v8
docker-push: docker-build

#----------------------------------------------------------------------------------
# Examples
#----------------------------------------------------------------------------------

.PHONY: activeconn
activeconn: $(EXAMPLES_DIR)/activeconn
.PHONY: tcpconnect
tcpconnect: $(EXAMPLES_DIR)/tcpconnect
.PHONY: exitsnoop
exitsnoop: $(EXAMPLES_DIR)/exitsnoop
.PHONY: oomkill
oomkill: $(EXAMPLES_DIR)/oomkill
.PHONY: capable
capable: $(EXAMPLES_DIR)/capable
.PHONY: tcpconnlat
tcpconnlat: $(EXAMPLES_DIR)/tcpconnlat


$(EXAMPLES_DIR)/%:
	$(OUTDIR)/bee-linux-amd64 build $@/$*.c $(HUB)/$(REPO_NAME)/$*:$(VERSION)
	$(OUTDIR)/bee-linux-amd64 push $(HUB)/$(REPO_NAME)/$*:$(VERSION)

.PHONY: release-examples
release-examples: activeconn tcpconnect exitsnoop oomkill capable tcpconnlat

#----------------------------------------------------------------------------------
# CLI
#----------------------------------------------------------------------------------

COMPRESSION_FLAGS=-s -w
CMD_DIR := cmd

$(OUTDIR)/bee-linux-amd64: $(SOURCES)
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -ldflags="$(LDFLAGS) $(COMPRESSION_FLAGS)" -gcflags=$(GCFLAGS) -o $@ cmd/bee/main.go

.PHONY: bee-linux-amd64
bee-linux-amd64: $(OUTDIR)/bee-linux-amd64.sha256
$(OUTDIR)/bee-linux-amd64.sha256: $(OUTDIR)/bee-linux-amd64
	sha256sum $(OUTDIR)/bee-linux-amd64 > $@

$(OUTDIR)/bee-linux-arm64: $(SOURCES)
	CGO_ENABLED=0 GOARCH=arm64 GOOS=linux go build -ldflags="$(LDFLAGS) $(COMPRESSION_FLAGS)" -gcflags=$(GCFLAGS) -o $@ cmd/bee/main.go

.PHONY: bee-linux-arm64
bee-linux-arm64: $(OUTDIR)/bee-linux-arm64.sha256
$(OUTDIR)/bee-linux-arm64.sha256: $(OUTDIR)/bee-linux-arm64
	sha256sum $(OUTDIR)/bee-linux-arm64 > $@

.PHONY: build-cli
build-cli: bee-linux-amd64 bee-linux-arm64

.PHONY: install-cli
install-cli:
	CGO_ENABLED=0 go install -ldflags="$(LDFLAGS)" -gcflags=$(GCFLAGS) ./bee

CMD_DIR := cmd
BEE_DIR := $(CMD_DIR)/bee
$(OUTDIR)/Dockerfile-bee: $(BEE_DIR)/Dockerfile-bee
	cp $< $@

.PHONY: docker-build-bee
docker-build-bee: build-cli $(OUTDIR)/Dockerfile-bee
	$(DOCKER) build $(OUTDIR) -f $(OUTDIR)/Dockerfile-bee -t $(HUB)/bumblebee/bee:$(VERSION)

.PHONY: docker-push-bee
docker-push-bee: docker-build-bee
	$(DOCKER) push $(HUB)/bumblebee/bee:$(VERSION)


#----------------------------------------------------------------------------------
# Operator
#----------------------------------------------------------------------------------

$(OUTDIR)/operator-linux-amd64: $(SOURCES)
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -ldflags="$(LDFLAGS) $(COMPRESSION_FLAGS)" -gcflags=$(GCFLAGS) -o $@ cmd/operator/main.go

.PHONY: operator-linux-amd64
operator-linux-amd64: $(OUTDIR)/operator-linux-amd64

$(OUTDIR)/operator-linux-arm64: $(SOURCES)
	CGO_ENABLED=0 GOARCH=arm64 GOOS=linux go build -ldflags="$(LDFLAGS) $(COMPRESSION_FLAGS)" -gcflags=$(GCFLAGS) -o $@ cmd/operator/main.go

.PHONY: operator-linux-arm64
operator-linux-arm64: $(OUTDIR)/operator-linux-arm64


.PHONY: build-operator
build-operator: operator-linux-amd64 operator-linux-arm64

OPERATOR_DIR := $(CMD_DIR)/operator
$(OUTDIR)/Dockerfile-operator: $(OPERATOR_DIR)/Dockerfile-operator
	cp $< $@

OPERATOR_DIR := cmd/operator
.PHONY: docker-build-operator
docker-build-operator: build-operator $(OUTDIR)/Dockerfile-operator
	$(DOCKER) build $(OUTDIR) -f $(OUTDIR)/Dockerfile-operator -t $(HUB)/bumblebee/operator:$(VERSION)

.PHONY: docker-push-operator
docker-push-operator: docker-build-operator
	$(DOCKER) push $(HUB)/bumblebee/operator:$(VERSION)

##----------------------------------------------------------------------------------
## Release
##----------------------------------------------------------------------------------

.PHONY: upload-github-release-assets
upload-github-release-assets: build-cli
ifeq ($(RELEASE),"true")
	go run ci/release_assets.go
endif

.PHONY: regen-vmlinux
regen-vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > builder/vmlinux.h

##----------------------------------------------------------------------------------
## Helm
##----------------------------------------------------------------------------------

.PHONY: upload-github-release-assets
upload-github-release-assets: build-cli
ifeq ($(RELEASE),"true")
	go run ci/release_assets.go
endif

release-helm: generated-code
release-helm: package-helm-bumblebee
release-helm: fetch-helm-bumblebee
release-helm: index-helm-bumblebee
release-helm: release-helm-bumblebee

HELM_ROOTDIR ?= install/helm
HELM_OUTPUT_DIR := $(HELM_ROOTDIR)/_output
CHART_OUTPUT_DIR := $(HELM_OUTPUT_DIR)/charts

package-helm-%:
	helm package --dependency-update --destination $(CHART_OUTPUT_DIR)/$* $(HELM_ROOTDIR)/$*

fetch-helm-%:
	gsutil -m rsync -r gs://bumblebee-helm/$* $(CHART_OUTPUT_DIR)/$*

index-helm-%:
	helm repo index $(CHART_OUTPUT_DIR)/$*

release-helm-%:
	gsutil -h "Cache-Control:no-cache,max-age=0" -m rsync -r $(CHART_OUTPUT_DIR)/$* gs://gloo-mesh-enterprise/$*

clean-helm-%:
	rm -rf $(HELM_ROOTDIR)/$*/charts/
	rm -f $(HELM_ROOTDIR)/$*/chart.lock
	rm -f $(HELM_ROOTDIR)/$*/chart.yaml
	rm -f $(HELM_ROOTDIR)/$*/values.yaml

