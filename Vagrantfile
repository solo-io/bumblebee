
Vagrant.configure("2") do |config|
    config.vm.box = "generic/ubuntu2110"
    config.vm.define :impish
    config.vm.hostname = "impish"
    config.vm.synced_folder ".", "/source"
    config.vm.provision "shell", inline: <<-SHELL
      # install llvm:
      export DEBIAN_FRONTEND=noninteractive
      export LLVM_VERSION=13
      wget https://apt.llvm.org/llvm.sh
      bash ./llvm.sh "$LLVM_VERSION"
      rm ./llvm.sh
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