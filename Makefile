#----------------------------------------------------------------------------------
# Versioning
#----------------------------------------------------------------------------------
OUTDIR?=_output
HUB?=ghcr.io/solo-io
REPO_NAME?=bumblebee
EXAMPLES_DIR?=examples


RELEASE := "true"
ifeq ($(TAGGED_VERSION),)
	TAGGED_VERSION := $(shell git describe --tags --dirty --always)
	RELEASE := "false"
endif
# In iron mountain escrow action we pass in the tag as TAGGED_VERSION: ${{ github.ref }}.
# This tag has the refs/tags prefix, which we need to remove here.
export VERSION ?= $(shell echo $(TAGGED_VERSION) | sed -e "s/^refs\/tags\///" | cut -c 2-)

LDFLAGS := "-X github.com/solo-io/bumblebee/pkg/internal/version.Version=$(VERSION)"
GCFLAGS := all="-N -l"

SOURCES := $(shell find . -name "*.go" | grep -v test.go)

.PHONY: clean
clean:
	rm -f $(EXAMPLES_DIR)/**/*.o
	rm -rf $(OUTDIR)

#----------------------------------------------------------------------------------
# Build Container
#----------------------------------------------------------------------------------
PUSH_CMD:=
PLATFORMS?=linux/amd64
DOCKER := docker
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


$(EXAMPLES_DIR)/%:
	$(OUTDIR)/bee-linux-amd64 build $@/$*.c $(HUB)/$(REPO_NAME)/$*:$(VERSION)
	$(OUTDIR)/bee-linux-amd64 push $(HUB)/$(REPO_NAME)/$*:$(VERSION)

.PHONY: release-examples
release-examples: activeconn tcpconnect

#----------------------------------------------------------------------------------
# CLI
#----------------------------------------------------------------------------------


$(OUTDIR)/bee-linux-amd64: $(SOURCES)
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -ldflags=$(LDFLAGS) -gcflags=$(GCFLAGS) -o $@ bee/main.go

.PHONY: bee-linux-amd64
bee-linux-amd64: $(OUTDIR)/bee-linux-amd64.sha256
$(OUTDIR)/bee-linux-amd64.sha256: $(OUTDIR)/bee-linux-amd64
	sha256sum $(OUTDIR)/bee-linux-amd64 > $@

$(OUTDIR)/bee-linux-arm64: $(SOURCES)
	CGO_ENABLED=0 GOARCH=arm64 GOOS=linux go build -ldflags=$(LDFLAGS) -gcflags=$(GCFLAGS) -o $@ bee/main.go

.PHONY: bee-linux-arm64
bee-linux-arm64: $(OUTDIR)/bee-linux-arm64.sha256
$(OUTDIR)/bee-linux-arm64.sha256: $(OUTDIR)/bee-linux-arm64
	sha256sum $(OUTDIR)/bee-linux-arm64 > $@

.PHONY: build-cli
build-cli: bee-linux-amd64 bee-linux-arm64

.PHONY: install-cli
install-cli:
	CGO_ENABLED=0 go install -ldflags=$(LDFLAGS) -gcflags=$(GCFLAGS) ./bee

BEE_DIR := bee
$(OUTDIR)/Dockerfile: $(BEE_DIR)/Dockerfile
	cp $< $@
build-cli-docker: build-cli $(OUTDIR)/Dockerfile
	docker build $(OUTDIR) -f $(OUTDIR)/Dockerfile -t $(HUB)/bumblebee/bee:$(VERSION)

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
