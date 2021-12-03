# eBPF Image specifications

## Introduction

The eBPF Image specification defines how to bundle eBPF kernel programs as container images. A compatible eBPF image consists of a eBPF binary file, and Architecture metadata. Currently, the cli in this repo `bee` is the only way to run these images, although the spec is intended to be generic and to provide a standard mechanism to manage the building and running of eBPF modules by any compatible loader.

## Terminology:

| Term                               | Definition                                       |
|------------------------------------|--------------------------------------------------|
| eBPF Module                        | The distributable, loadable, and executable unit of code in WebAssembly. 
| eBPF Image Specification           | The specification for storing eBPF modules as container images.



## eBPF Artifact Image Specification v0.0.0

- [Description](#description)
    - [Layers](#layers)
    - [Running OCI Images with Envoy](#running-oci-images-with-envoy)
- [Format](#format)

### Description:

#### Overview:

Most of the data necessary to running a BTF enabled eBPF program, are contained within the binary iteslf, so forunately not much other information needs to be stored alongside it.

#### Layers:

The content layer always consists of the eBPF module binary. 

The config layer consists of a JSON-formatted string, which currently contains no information, but is available for configuration later should the need arise 

For the sake of simplicity, the specification only supports a single module per image.

#### Running OCI Images with bee:

`bee` takes advantage of a newer linux kernel technology called BTF, so in order to run `eBPF` images, a BTF enabled kernel is required.

Once this has been verified, these images can be run using `bee run IMAGE_NAME`.


### Format:

The WASM OCI Artifact Spec consists of two layers bundled together:
- A layer specifying configuration for the target runtime
- A layer containing the compiled eBPF module itself

Each layer is associated with its own Media Type, which is stored in the OCI Descriptor for that layer:

| Media Type | Type | Description |
|------------|------|-------------|
| application/ebpf.oci.image.config.v1+json | JSON Object | Configuration for the Target eBPF module.
| application/ebpf.oci.image.program.v1+binary | binary data (byte array) | Compiled ELF of eBPF module |

#### Example:

The following descriptors provide an example of the OCI Image descriptors for an Envoy WASM Filter stored according to the specification:
```
[
  {
    "mediaType": "application/ebpf.oci.image.config.v1+json",
    "digest": "sha256:d0a165298ae270c5644be8e9938036a3a7a5191f6be03286c40874d761c18abf",
    "size": 15,
    "annotations": {
      "org.opencontainers.image.title": "config.json"
    }
  },
  {
    "mediaType": "application/ebpf.oci.image.program.v1+binary",
    "digest": "sha256:5e82b945b59d03620fb360193753cbd08955e30a658dc51735a0fcbc2163d41c",
    "size": 1043056,
    "annotations": {
      "org.opencontainers.image.title": "program.o"
    }
  }
]
```

You can use the `bee` tool to take new or existing module code and package it according to the eBPF OCI Spec.

## Want more info?

[eBPF]: https://ebpf.io/
[OCI Artifact]: https://github.com/opencontainers/artifacts