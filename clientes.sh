#!/usr/bin/env bash

if [ "${#}" -ne 1 ]; then
    echo "Necessário passar a ação como parâmetro (parar ou iniciar)"
    echo "./clientes.sh parar ou ./clientes.sh iniciar"
    exit 1
fi

if [ $( docker images --format table | grep -c 'sbrc26-clientes' ) -ne 1 ]; then
    echo "Uma ou mais imagem(ns) de servidor(es) está(ão) faltando. Certifique-se de ter executado o build-images.sh conforme a documentação."
    exit 1
fi

function PARAR {
    while read -r SERVER; do
        docker rm -f "${SERVER}"
    done < <( docker ps -a | grep 'sbrc26-cliente-' | awk '{print $1}' )
}

function INICIAR {
    NUM_CLIENT=$( docker ps -a | grep 'sbrc26-cliente-' | wc -l )
    NEXT=$(( NUM_CLIENT + 1 ))
    docker run -d --rm --name sbrc26-cliente-${NEXT} sbrc26-clientes:latest
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