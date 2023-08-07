
Vagrant.configure("2") do |config|
    # amd64
    config.vm.box = "generic/ubuntu2204"
    # arm64
    # config.vm.box = "jharoian3/ubuntu-22.04-arm64"
    config.vm.define :jammy
    config.vm.hostname = "jammy"
    config.vm.synced_folder ".", "/source"
    config.vm.provision "shell", inline: <<-SHELL
      # fix DNS problem
      rm -f /etc/resolv.conf
      ln -s /run/systemd/resolve/resolv.conf /etc/resolv.conf
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
