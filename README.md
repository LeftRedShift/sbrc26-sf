# sbrc26-sf - Salão de Ferramentas SBRC 2026

### Ambiente de desenvolvimento (apenas para referência):
- Sistema Operacional Host: Kubuntu Desktop 24.04 LTS
- Processador AMD Ryzen 5 5600X
- 32 GB de RAM
- GPU GeForce RTX 3070Ti com 8 GB de VRAM
- 1TB de armazenamento
- Internet 500Mbps de download / 50Mbps de upload

### Ambiente e configurações mínimas para execução:
- Dispositivo Bare-metal ou VM com Sistema Operacional baseado em Ubuntu 24.04 LTS
  - Computador com Web Browser com acesso à rede da instalação (caso a instalação seja realizada em outro servidor ou VM)
- Processador baseado em arquitetura x86/AMD64
- 8 GB de RAM
- 15GB de espaço disponível
- Acesso à internet
- Usuário com permissão de execução de `sudo`

> Os pacotes que serão instalados são bastante comuns e não devem causar nenhum tipo de distúrbio no ambiente onde for instalado, apesar disto, sugere-se fortemente que a instalação desta ferramenta seja realizada em uma instalação nova do Sistema Operacional própria para este fim, no intuito de não interferir de alguma forma não intencional no ambiente do operador que estará efetuando a instalação.

### Clonar e entrar no repositório:
```
git clone https://github.com/LeftRedShift/sbrc26-sf.git && cd sbrc26-sf/
```

### Instalação automatizada:

#### Estando no diretório raiz deste repositório, tornar executável o script `instalador1.sh`::

```
chmod +x instalador1.sh
```

#### Instalar **todas as dependências** e instalar a ferramenta, rodando o script `instalador1.sh`:

```
./instalador1.sh
```
> Será solicitada a senha do usuário para efetuar as instalações que necessitem de `sudo`.
Aguarde o término da instalação do `instalador1.sh` e execute o próximo comando.

```
newgrp docker
```

#### Construir todas as imagens e iniciar a ferramenta, rodando o script `instalador2.sh`:


```
./instalador2.sh
```

**Nota:** _No ambiente de desenvolvimento mencionado acima, os procedimentos de instalação levaram em média `11 minutos e 30 segundos` para concluir na totalidade, baixando cerca de 2.3GB de dados pela internet e resultando no uso de 12GB de espaço adicional em disco._

Concluída a instalação, a ferramenta estará disponível acessando http://endereço.ip.da.instalação:8501/ ou http://127.0.0.1:8501/ (caso o local da instalação possua um Web Browser).

### Parar ou iniciar os servidores (pós conclusão da instalação, caso necessário):

#### Estando no diretório raiz deste repositório, tornar executável o script `servidores.sh`::

```
chmod +x servidores.sh
```

#### Estando no diretório raiz deste repositório, para parar e remover os contêiners dos servidores:

```
./servidores.sh parar
```

#### Iniciar os contêiners dos servidores:

```
./servidores.sh iniciar
```

### Parar ou iniciar os clientes "benignos" (pós conclusão da instalação caso deseje):

#### Estando no diretório raiz deste repositório, para parar e remover os contêiners dos clientes:

```
./clientes.sh parar
```

#### Iniciar um cliente:

```
./clientes.sh iniciar
```
> O comando `./clientes.sh iniciar` inicia mais um cliente, independente de quantos já estejam rodando.



#### Parar e remover containers e imagens residuais (limpeza completa do ambiente).

```
while read -r CONT; do docker rm -f ${CONT}; done < <( docker ps -a | grep 'sbrc26-' | awk '{print $1}' )
while read -r IMG; do docker rmi -f ${IMG}; done < <( docker images --format table | grep 'sbrc26-' | awk '{print $3}' )

```


## Estrutura do projeto**:
```
sbrc26-sf
|
├── assets/                   # Diretório auxiliar para documentação
├── captures/                 # Diretório de armazenamento das capturas .pcap
├── datasets/                 # Diretório de datasets gerados
├── docker/                   # Repositório de contêineres
│		 ├── atacantes/           # Diretório dos contêineres atacantes
│		 ├── build-images.sh      # Script de construção de todas as imagens
│		 ├── clientes/            # Diretório dos contêineres clientes (benignos)
│		 └── servidores/          # Diretório dos contêineres servidores alvo
├── features/                 # Diretório dos CSV de extração de features
├── modules/                  # Diretório dos módulos da ferramenta
│		 ├── datasets.py          # Módulo de geração de datasets
│		 ├── features.py          # Módulo de extração de features
│		 ├── registry.py          # Módulo de declaração de especificações dos contêineres
│		 └── runners.py           # Módulo de ações práticas da ferramenta
├── clientes.sh               # Script para controlar manualmente os contêineres de clientes
├── ferramenta.py             # Arquivo principal da ferramenta
├── instalador1.sh            # Script automatizado para instalação das dependências
├── instalador2.sh            # Script para geração das imagens e artefatos Docker
├── LICENSE                   # Arquivo de licença da ferramenta (GNU GENERAL PUBLIC LICENSE)
├── README.md                 # Este arquivo README.ms
├── requirements.txt          # Arquivo com requisitos de pacotes Python do instalador PIP
└── servidores.sh             # Script para controlar manualmente os servidores alvo
```