Vagrant.configure("2") do |config|
  config.vm.box_check_update = false

  # Node A: ISF Symbol Builder
  config.vm.define "isf-build" do |builder|
    builder.vm.box = "alvistack/ubuntu-22.04"
    builder.vm.box_version = "20260108.1.1"
    builder.vm.hostname = "isf-build"
    builder.vm.synced_folder ".", "/vagrant", disabled: true
    builder.vm.provision "shell", inline: "echo 'Acquire::Queue-Mode \"access\"; Acquire::http::Pipeline-Depth \"10\";' > /etc/apt/apt.conf.d/99parallel"

    builder.vm.provider :libvirt do |lv|
      lv.memory = 4096
      lv.cpus = 4
      lv.disk_driver :cache => 'unsafe'
      #lv.cpu_mode = "host-passthrough"
    end

    builder.vm.provision "ansible" do |ansible|
      ansible.playbook = "ansible/isf_build.yml"
      ansible.verbose = "v"
      ansible.raw_arguments = ["--diff"]
    end
  end

  # Node B: Ubuntu 22.04 Victim
  config.vm.define "victim-ubuntu22" do |victim|
    victim.vm.box = "alvistack/ubuntu-22.04"
    victim.vm.box_version = "20260108.1.1"
    victim.vm.hostname = "victim-ubuntu22"
    victim.vm.synced_folder ".", "/vagrant", disabled: true

    victim.vm.provider :libvirt do |vb|
      vb.memory = 2048
      vb.cpus = 2
    end

    victim.vm.network "private_network",
      ip: "192.168.56.10",
      libvirt__network_name: "forensic-lab-net",
      libvirt__dhcp_enabled: false,
      libvirt__forward_mode: "none",
      libvirt__hostname: "victim-ubuntu22"

    victim.vm.provision "ansible" do |ansible|
      ansible.playbook = "ansible/victim_baseline.yml"
      ansible.verbose = "v"
      ansible.raw_arguments = ["--diff"]
    end
  end
end
