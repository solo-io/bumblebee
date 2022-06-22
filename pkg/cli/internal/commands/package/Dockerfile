ARG BEE_IMAGE

FROM $BEE_IMAGE

USER root
COPY ./store /root/.bumblebee/store/

ARG BPF_IMAGE
ENV BPF_IMAGE=$BPF_IMAGE
CMD ./bee run --no-tty ${BPF_IMAGE}
