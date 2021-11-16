#----------------------------------------------------------------------------------
# Versioning
#----------------------------------------------------------------------------------
OUTDIR ?= _output
HUB ?= "gcr.io/"


RELEASE := "true"
ifeq ($(TAGGED_VERSION),)
	TAGGED_VERSION := $(shell git describe --tags --dirty --always)
	RELEASE := "false"
endif
# In iron mountain escrow action we pass in the tag as TAGGED_VERSION: ${{ github.ref }}.
# This tag has the refs/tags prefix, which we need to remove here.
export VERSION ?= $(shell echo $(TAGGED_VERSION) | sed -e "s/^refs\/tags\///" | cut -c 2-)

LDFLAGS := "-X github.com/solo-io/ebpf/pkg/internal/version.Version=$(VERSION)"
GCFLAGS := all="-N -l"

SOURCES := $(shell find . -name "*.go" | grep -v test.go)

#----------------------------------------------------------------------------------
# Build Container
#----------------------------------------------------------------------------------

docker-build:
#   may run into issues with apt-get and the apt.llvm.org repo, in which case use --no-cache to build
#   e.g. `docker build --no-cache ./builder -f builder/Dockerfile -t $(HUB)gloobpf/bpfbuilder:$(VERSION)`
	docker build ./builder -f builder/Dockerfile -t $(HUB)gloobpf/bpfbuilder:$(VERSION)

docker-push:
	docker push gcr.io/gloobpf/bpfbuilder:$(VERSION) 

#----------------------------------------------------------------------------------
# CLI
#----------------------------------------------------------------------------------


$(OUTDIR)/ebpfctl-linux-amd64: $(SOURCES)
	CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -ldflags=$(LDFLAGS) -gcflags=$(GCFLAGS) -o $@ ebpfctl/main.go

.PHONY: ebpfctl-linux-amd64
ebpfctl-linux-amd64: $(OUTDIR)/ebpfctl-linux-amd64.sha256
$(OUTDIR)/ebpfctl-linux-amd64.sha256: $(OUTDIR)/ebpfctl-linux-amd64
	sha256sum $(OUTDIR)/ebpfctl-linux-amd64 > $@

$(OUTDIR)/ebpfctl-linux-arm64: $(SOURCES)
	CGO_ENABLED=0 GOARCH=arm64 GOOS=linux go build -ldflags=$(LDFLAGS) -gcflags=$(GCFLAGS) -o $@ ebpfctl/main.go

.PHONY: ebpfctl-linux-arm64
ebpfctl-linux-arm64: $(OUTDIR)/ebpfctl-linux-arm64.sha256
$(OUTDIR)/ebpfctl-linux-arm64.sha256: $(OUTDIR)/ebpfctl-linux-arm64
	sha256sum $(OUTDIR)/ebpfctl-linux-arm64 > $@

.PHONY: build-cli
build-cli: ebpfctl-linux-amd64 ebpfctl-linux-arm64

.PHONY: install-cli
install-cli:
	CGO_ENABLED=0 go install -ldflags=$(LDFLAGS) -gcflags=$(GCFLAGS) ebpfctl/main.go

##----------------------------------------------------------------------------------
## Release
##----------------------------------------------------------------------------------

.PHONY: upload-github-release-assets
upload-github-release-assets: build-cli
ifeq ($(RELEASE),"true")
	go run ci/release_assets.go
endif
