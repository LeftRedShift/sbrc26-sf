#!/usr/bin/env bash

if [ "${#}" -ne 1 ]; then
    echo "Necessário passar a ação como parâmetro (parar ou iniciar)"
    echo "./servers.sh parar ou ./servers.sh iniciar"
    exit 1
fi

if [ $( docker images --format table | grep -c sbrc26-servidor ) -ne 7 ]; then
    echo "Uma ou mais imagem(ns) de servidor(es) está(ão) faltando. Certifique-se de ter executado o build-images.sh conforme a documentação."
    exit 1
fi

function PARAR {
    while read -r SERVER; do
        docker rm -f "${SERVER}"
    done < <( docker ps -a | grep 'sbrc26-servidor-' | awk '{print $1}' )
}

function INICIAR {
    if [ $( docker ps -a | grep -c 'docker ps -a | grep') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-http-server -p 8080:80 sbrc26-servidor-http-server:latest
    fi
    if [ $( docker ps -a | grep -c 'docker ps -a | grep') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-ssh-server -p 2222:22 sbrc26-servidor-ssh-server:latest
    fi
    if [ $( docker ps -a | grep -c 'docker ps -a | grep') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-smb-server -p 139:139 -p 445:445 -p 137:137/udp -p 138:138/udp sbrc26-servidor-smb-server:latest
    fi
    if [ $( docker ps -a | grep -c 'docker ps -a | grep') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-mqtt-broker -p 1883:1883 -p 9001:9001 sbrc26-servidor-mqtt-broker:latest
    fi
    if [ $( docker ps -a | grep -c 'docker ps -a | grep') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-coap-server -p 5683:5683 -p 5683:5683/udp sbrc26-servidor-coap-server:latest
    fi
    if [ $( docker ps -a | grep -c 'docker ps -a | grep') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-telnet-server -p 2323:23 sbrc26-servidor-telnet-server:latest
    fi
    if [ $( docker ps -a | grep -c 'docker ps -a | grep') -eq 0 ]; then
        docker run -d --rm --name sbrc26-servidor-ssl-heartbleed -p 8443:443 sbrc26-servidor-ssl-heartbleed:latest
    fi
}

case ${1} in
    parar)
        PARAR
        ;;
    iniciar)
        INICIAR
        ;;
    *)
        echo "Necessário passar a ação como parâmetro (parar ou iniciar)"
        ;;
esac