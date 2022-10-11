#!/bin/bash

#update
sudo apt-get -y update

#install go-lang
if [[ -z "$GOPATH" ]];then
echo "[+] It looks like go is not installed, would you like to install it now"
PS3="Please select an option : "
choices=("yes" "no")
select choice in "${choices[@]}"; do
        case $choice in
                yes)

					echo "[+] Installing Golang"
					sudo apt-get install golang				
					sleep 1
					break
					;;
				no)
					echo "[+] Please install go and rerun this script"
					echo "[+] Aborting installation..."
					exit 1
					;;
	esac	
done
fi

#Don't forget to set up AWS credentials!
echo "[+] Don't forget to set up AWS credentials!"
sudo apt install awscli
echo "[+] Don't forget to set up AWS credentials!"

#create a tools folder in ~/
mkdir ~/tools
cd ~/tools/

#install aquatone
echo "[+] Installing Aquatone"
go get github.com/michenriksen/aquatone
echo "[+] done"

#install JSParser
echo "[+] installing JSParser"
git clone https://github.com/nahamsec/JSParser.git
cd JSParser*
sudo python setup.py install
cd ~/tools/
echo "[+] done"

#install sublist3r
echo "[+] installing Sublist3r"
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r*
pip install -r requirements.txt
cd ~/tools/
echo "[+] done"

#install teh_s3_bucketeers
echo "[+] installing teh_s3_bucketeers"
git clone https://github.com/tomdev/teh_s3_bucketeers.git
cd ~/tools/
echo "[+] done"

#install wpscan
echo "[+] installing wpscan"
git clone https://github.com/wpscanteam/wpscan.git
cd wpscan*
sudo gem install bundler && bundle install --without test
cd ~/tools/
echo "[+] done"

#install dirsearch
echo "[+] installing dirsearch"
git clone https://github.com/maurosoria/dirsearch.git
cd ~/tools/
echo "[+] done"

#install lazys3
echo "[+] installing lazys3"
git clone https://github.com/nahamsec/lazys3.git
cd ~/tools/
echo "[+] done"

#install vhost discovery
echo "[+] installing virtual host discovery"
git clone https://github.com/jobertabma/virtual-host-discovery.git
cd ~/tools/
echo "[+] done"

#install sqlmap
echo "[+] installing sqlmap"
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd ~/tools/
echo "[+] done"

#install knockpy
echo "[+] installing knock.py"
git clone https://github.com/guelfoweb/knock.git
cd ~/tools/
echo "[+] done"

#install lazyrecon
echo "[+] installing lazyrecon"
git clone https://github.com/nahamsec/lazyrecon.git
cd ~/tools/
echo "[+] done"

#install nmap
echo "[+] installing nmap"
sudo apt-get install -y nmap
echo "[+] done"

#install massdns
echo "[+] installing massdns"
git clone https://github.com/blechschmidt/massdns.git
cd ~/tools/massdns
make
cd ~/tools/
echo "[+] done"

#install asnlookup
echo "[+] installing asnlookup"
git clone https://github.com/yassineaboukir/asnlookup.git
cd ~/tools/asnlookup
pip install -r requirements.txt
cd ~/tools/
echo "[+] done"

#install unfurl
echo "[+] installing unfurl"
go get -u github.com/tomnomnom/unfurl 
echo "[+] done"

#install crtndstry
echo "[+] installing crtndstry"
git clone https://github.com/nahamsec/crtndstry.git
echo "[+] done"

#Download seclists
echo "[+] downloading Seclists"
cd ~/tools/
git clone https://github.com/danielmiessler/SecLists.git
cd ~/tools/SecLists/Discovery/DNS/
##THIS FILE BREAKS MASSDNS AND NEEDS TO BE CLEANED
cat dns-Jhaddix.txt | head -n -14 > clean-jhaddix-dns.txt
cd ~/tools/
echo "[+] done"

#installing other go-tools
echo "[+] Installing assetfinder"
go install github.com/tomnomnom/assetfinder@latest >/dev/null 2>&1
echo "[+] Installing subfinder"
GO111MODULE=on go get -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder >/dev/null 2>&1
echo "[+] Installing Nuclei"
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei >/dev/null 2>&1
echo "[+] Installing Dnsx"
go get -v github.com/projectdiscovery/dnsx/cmd/dnsx >/dev/null 2>&1
echo "[+] Installing Httprobe"
go get -u github.com/tomnomnom/httprobe >/dev/null 2>&1
echo "[+] Installing waybackurls"
go install github.com/tomnomnom/waybackurls@latest >/dev/null 2>&1
echo "[+] Installing anew"
go get -u github.com/tomnomnom/anew >/dev/null 2>&1
echo "[+] Installing Subzy"
go install github.com/lukasikic/subzy@latest >/dev/null 2>&1
echo "[+] Installing HTTPX"
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx >/dev/null 2>&1
echo "[+] Installation Completed"
echo "[+] Installing GF"
go get -u github.com/tomnomnom/gf
echo "[+] Cloning GF-Patterns from github..."
git clone https://github.com/1ndianl33t/Gf-Patterns
mkdir ~/.gf
echo "[+] Copying GF GF-Patterns to directoty..."
cp Gf-Patterns/*.json ~/.gf
