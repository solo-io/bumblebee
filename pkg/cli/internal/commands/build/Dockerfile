ARG BEE_VERSION=0.0.9

FROM ghcr.io/solo-io/bumblebee/bee:$BEE_VERSION

USER root
COPY ./store /root/.bumblebee/store/

CMD ["run", "tcpconnect"]
