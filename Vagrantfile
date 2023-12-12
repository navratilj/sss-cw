# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.define "box" do |box|
                box.vm.box = "ubuntu/bionic64"
                box.vm.hostname = "sss-demo"
                box.vm.provider "virtualbox" do |virtualbox|
        virtualbox.name="sss-demo"
    end
    config.vm.synced_folder ".", "/vagrant"
  config.vm.provision "shell", inline: 
    "sudo apt-get update -y"
  config.vm.provision "shell", inline: 
    "sudo apt install -y python3-pip gdb gcc-multilib"
  config.vm.provision "shell", inline: 
    "sudo pip3 install capstone"
  config.vm.provision "shell", inline: 
    "sudo -H python3 -m pip install ROPgadget"
  config.vm.provision "shell", inline: 
    "sudo apt install radare2"
 end
end
