#!/bin/bash


echo '=== i386 ==='
sudo dpkg --add-architecture i386 && sudo apt update
sudo apt install -y libc6:i386 libncurses5:i386 libstdc++6:i386 libc6-dev-i386

echo '=== Basic Util ==='
sudo apt install -y git curl wget unzip
sudo apt install -y hexer hexcurse binutils binwalk # binutils (strings, c++filt)
sudo apt install -y nmap netcat socat httpie

echo '=== gdb ==='
sudo apt install -y gdb
git clone https://github.com/longld/peda.git ${HOME}/.peda
git clone https://github.com/scwuaptx/Pwngdb ${HOME}/.Pwngdb
ln -b -s ${HOME}/.peda/.inputrc ${HOME}
cat > ${HOME}/.gdbinit <<EOF
source ~/.peda/peda.py
source ~/.Pwngdb/pwngdb.py
source ~/.Pwngdb/angelheap/gdbinit.py

set startup-with-shell off

define hook-run
python
import angelheap
angelheap.init_angelheap()
end
end
EOF

echo '=== pwntools, ropgadget, angr, one_gadget ==='
sudo apt install -y python3 python3-pip python-dev libssl-dev libffi-dev build-essential
sudo pip3 install --upgrade pip
sudo pip3 install --upgrade setuptools ropgadget
sudo pip3 install --upgrade pwntools angr
sudo pip3 install six==1.12.0 # for pwntools

sudo apt install -y ruby-dev
gem install one_gadget
