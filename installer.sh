#!/usr/bin/env bash

echo "Instalando pacotes necessários..."
sudo apt update
sudo apt install tshark tcpdump python3-venv cmake wireshark redis git ca-certificates curl -y
sudo dpkg-reconfigure wireshark-common
sudo chmod +x /usr/bin/dumpcap
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tcpdump)"
sudo apt remove $(dpkg --get-selections docker.io docker-compose docker-compose-v2 docker-doc podman-docker containerd runc | cut -f1)
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
sudo tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt update
echo "Instalando Docker Engine..."
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker
echo "Instalando a ferramenta..."
cd /home/experimento/ || exit 1
git clone https://github.com/LeftRedShift/sbrc26-sf.git
cd sbrc26-sf/ || exit 1
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
git clone https://github.com/ahlashkari/NTLFlowLyzer.git
cd NTLFlowLyzer
echo -e "\nsetuptools" >> requirements.txt
pip install -r requirements.txt
python3 setup.py install
cd ../
pip install -r requirements.txt
cd docker/ || exit 1
echo "Construindo os contêineres..."
docker build -t sbrc26-servidor-http-server -f servidores/http-server/Dockerfile .
docker run -d --rm --name sbrc26-servidor-http-server -p 8080:80 sbrc26-servidor-http-server:latest
docker build -t sbrc26-servidor-ssh-server -f servidores/ssh-server/Dockerfile .
docker run -d --rm --name sbrc26-servidor-ssh-server -p 2222:22 sbrc26-servidor-ssh-server:latest
docker build -t sbrc26-servidor-smb-server -f servidores/smb-server/Dockerfile .
docker run -it -d --rm --name sbrc26-servidor-smb-server -p 139:139 -p 445:445 -p 137:137/udp -p 138:138/udp sbrc26-servidor-smb-server:latest
docker build -t sbrc26-servidor-mqtt-broker -f servidores/mqtt-broker/Dockerfile .
docker run -it -d --rm --name sbrc26-servidor-mqtt-broker -p 1883:1883 -p 9001:9001 sbrc26-servidor-mqtt-broker:latest
docker build -t sbrc26-servidor-coap-server -f servidores/coap-server/Dockerfile .
docker run -d --rm --name sbrc26-servidor-coap-server -p 5683:5683 -p 5683:5683/udp sbrc26-servidor-coap-server:latest
docker build -t sbrc26-servidor-telnet-server -f servidores/telnet-server/Dockerfile .
docker run -d --rm --name sbrc26-servidor-telnet-server -p 2323:23 sbrc26-servidor-telnet-server:latest
docker build -t sbrc26-servidor-ssl-heartbleed -f servidores/ssl-heartbleed/Dockerfile .
docker run -d --rm --name sbrc26-servidor-ssl-heartbleed -p 8443:443 sbrc26-servidor-ssl-heartbleed:latest
docker build -t sbrc26-ataque-arp-scan -f atacantes/arp-scan/Dockerfile .
docker build -t sbrc26-ataque-arp-spoof -f atacantes/arp-spoof/Dockerfile .
docker build -t sbrc26-ataque-cdp-table-flood -f atacantes/cdp-table-flood/Dockerfile .
docker build -t sbrc26-ataque-coap-get-flood -f atacantes/coap-get-flood/Dockerfile .
docker build -t sbrc26-ataque-dhcp-starvation -f atacantes/dhcp-starvation/Dockerfile .
docker build -t sbrc26-ataque-dns-tunneling -f atacantes/dns-tunneling/Dockerfile .
docker build -t sbrc26-ataque-dos-http-simple -f atacantes/dos-http-simple/Dockerfile .
docker build -t sbrc26-ataque-dos-http-slowloris -f atacantes/dos-http-slowloris/Dockerfile .
docker build -t sbrc26-ataque-fin-flood -f atacantes/fin-flood/Dockerfile .
docker build -t sbrc26-ataque-icmp-flood -f atacantes/icmp-flood/Dockerfile .
docker build -t sbrc26-ataque-icmp-tunnel -f atacantes/icmp-tunnel/Dockerfile .
docker build -t sbrc26-ataque-idor-path-traversal -f atacantes/idor-path-traversal/Dockerfile .
docker build -t sbrc26-ataque-idor-url-parameter -f atacantes/idor-url-parameter/Dockerfile .
docker build -t sbrc26-ataque-ipv6-mld-flood -f atacantes/ipv6-mld-flood/Dockerfile .
docker build -t sbrc26-ataque-ipv6-ns-flood -f atacantes/ipv6-ns-flood/Dockerfile .
docker build -t sbrc26-ataque-ipv6-ra-flood -f atacantes/ipv6-ra-flood/Dockerfile .
docker build -t sbrc26-ataque-mqtt-bruteforce -f atacantes/mqtt-bruteforce/Dockerfile .
docker build -t sbrc26-ataque-mqtt-publisher -f atacantes/mqtt-publisher/Dockerfile .
docker build -t sbrc26-ataque-php-lfi-enumeration -f atacantes/php-lfi-enumeration/Dockerfile .
docker build -t sbrc26-ataque-ping-sweep -f atacantes/ping-sweep/Dockerfile .
docker build -t sbrc26-ataque-port-scanner-aggressive -f atacantes/port-scanner-aggressive/Dockerfile .
docker build -t sbrc26-ataque-port-scanner-os -f atacantes/port-scanner-os/Dockerfile .
docker build -t sbrc26-ataque-port-scanner-tcp -f atacantes/port-scanner-tcp/Dockerfile .
docker build -t sbrc26-ataque-port-scanner-udp -f atacantes/port-scanner-udp/Dockerfile .
docker build -t sbrc26-ataque-port-scanner-vulnerabilities -f atacantes/port-scanner-vulnerabilities/Dockerfile .
docker build -t sbrc26-ataque-psh-flood -f atacantes/psh-flood/Dockerfile .
docker build -t sbrc26-ataque-rst-flood -f atacantes/rst-flood/Dockerfile .
docker build -t sbrc26-ataque-smb-enumerating -f atacantes/smb-enumerating/Dockerfile .
docker build -t sbrc26-ataque-snmp-scanner -f atacantes/snmp-scanner/Dockerfile .
docker build -t sbrc26-ataque-sql-injection -f atacantes/sql-injection/Dockerfile .
docker build -t sbrc26-ataque-ssh-bruteforce -f atacantes/ssh-bruteforce/Dockerfile .
docker build -t sbrc26-ataque-stp-conf-flood -f atacantes/stp-conf-flood/Dockerfile .
docker build -t sbrc26-ataque-stp-tcn-flood -f atacantes/stp-tcn/Dockerfile .
docker build -t sbrc26-ataque-syn-flood -f atacantes/syn-flood/Dockerfile .
docker build -t sbrc26-ataque-telnet-bruteforce -f atacantes/telnet-bruteforce/Dockerfile .
docker build -t sbrc26-ataque-udp-flood -f atacantes/udp-flood/Dockerfile .
docker build -t sbrc26-ataque-web-dir-enumeration -f atacantes/web-dir-enumeration/Dockerfile .
docker build -t sbrc26-ataque-web-https-heartbleed -f atacantes/web-https-heartbleed/Dockerfile .
docker build -t sbrc26-ataque-web-post-bruteforce -f atacantes/web-post-bruteforce/Dockerfile .
docker build -t sbrc26-ataque-web-simple-scanner -f atacantes/web-simple-scanner/Dockerfile .
docker build -t sbrc26-ataque-web-wide-scanner -f atacantes/web-wide-scanner/Dockerfile .
docker build -t sbrc26-ataque-xss-scanner -f atacantes/xss-scanner/Dockerfile .
cd /home/experimento/sbrc26-sf/ || exit 1
streamlit run ferramenta.py &
