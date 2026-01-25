#!/usr/bin/env bash

. /venv/bin/activate

function SMB() {
     echo "Executando SMB"
     /tmp/smb-expect.sh "client" "badpass" "192.168.0.111"
}
function SSH() {
    echo "Executando SSH"
    /tmp/ssh-expect.sh "client" "192.168.0.111" "2222"
}

function TELNET() {
    echo "Executando TELNET"
    /tmp/telnet-expect.sh "192.168.0.111" "2222"
}

function WEB() {
    echo "Executando HTTP"
    /tmp/web-client.sh "192.168.0.111" "8080"
}

function SSL() {
    echo "Executando HTTPS"
    /tmp/web-client.sh "192.168.0.111" "8443"
}

function COAP() {
    echo "Executando COAP"
    /venv/bin/python3 /tmp/coap-client.py "192.168.0.111"
}

function MQTT() {
    echo "Executando MQTT"
    mosquitto_pub -h "192.168.0.111" -i mosq_pub1 -t "Client test" -m "Message with ID: 0"
}

CLIENTS=("WEB" "SMB" "SSH" "TELNET" "SSL" "COAP" "MQTT")
LENGHT=${#CLIENTS[@]}
function PICK() {
  CLIENT="${CLIENTS[$((RANDOM % LENGHT))]}"
  $CLIENT
}

while true; do
    SEC=$(( 1 + $RANDOM % 5 ))
    CSEC=$(( 1 + $RANDOM % 5 ))
    sleep "${SEC}.${CSEC}"
    PICK &
done 