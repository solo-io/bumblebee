FROM debian:bullseye

RUN apt-get update && \
    apt-get -y install lsb-release wget software-properties-common gnupg file git make

RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN add-apt-repository "deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-13 main"
RUN apt-get update

RUN apt-get install -y clang-13 lldb-13 lld-13 clangd-13 make man-db
RUN apt-get install -y bpftool libbpf-dev

# non package installed default include directory
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /usr/local/include/vmlinux.h

ADD build.sh /usr/local/bin

RUN mkdir /usr/src/bpf/
WORKDIR /usr/src/bpf

ENTRYPOINT ["build.sh"]
