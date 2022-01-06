
Vagrant.configure("2") do |config|
    # amd64
    config.vm.box = "generic/ubuntu2110"
    # arm64
    # config.vm.box = "nickschuetz/ubuntu-21.10-arm64"
    config.vm.define :impish
    config.vm.hostname = "impish"
    config.vm.synced_folder ".", "/source"
    config.vm.provision "shell", inline: <<-SHELL
      # install llvm:
      export DEBIAN_FRONTEND=noninteractive
      export LLVM_VERSION=13
      curl -sL https://apt.llvm.org/llvm.sh "$LLVM_VERSION" | bash
      apt-get -qq update
      # bpf related deps:
      apt-get -qq install linux-headers-$(uname -r) linux-tools-$(uname -r) libbpf-dev
      # dev tools:
      apt-get -qq install -y golang docker.io make
      usermod -aG docker vagrant
      # add headers:
      bpftool btf dump file /sys/kernel/btf/vmlinux format c > /usr/local/include/vmlinux.h
      cp /source/builder/solo_types.h /usr/local/include/
    SHELL
end
