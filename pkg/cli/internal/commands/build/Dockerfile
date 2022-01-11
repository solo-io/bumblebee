ARG BEE_IMAGE=ghcr.io/solo-io/bumblebee/bee
ARG BEE_TAG=latest

FROM $BEE_IMAGE:$BEE_TAG

USER root
COPY ./store /root/.bumblebee/store/

ARG BPF_IMAGE
ENV BPF_IMAGE=$BPF_IMAGE
CMD ./bee-linux-amd64 run ${BPF_IMAGE}
