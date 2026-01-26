#!/usr/bin/env bash

. /venv/bin/activate

TARGET="${1}"

function SMB() {
     echo "Executando SMB"
     /tmp/smb-expect.sh "client" "badpass" "${TARGET}"
}
function SSH() {
    echo "Executando SSH"
    /tmp/ssh-expect.sh "client" "${TARGET}" "2222"
}

function TELNET() {
    echo "Executando TELNET"
    /tmp/telnet-expect.sh "${TARGET}" "2222"
}

function WEB() {
    echo "Executando HTTP"
    /tmp/web-client.sh "${TARGET}" "8080"
}

function SSL() {
    echo "Executando HTTPS"
    /tmp/web-client.sh "${TARGET}" "8443"
}

function COAP() {
    echo "Executando COAP"
    /venv/bin/python3 /tmp/coap-client.py "${TARGET}"
}

function MQTT() {
    echo "Executando MQTT"
    mosquitto_pub -h "${TARGET}" -i mosq_pub1 -t "Client test" -m "Message with ID: 0"
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