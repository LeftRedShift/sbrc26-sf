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

#### Construir **todas as imagens**, subir os servidores e disponibilizar o acesso à ferramenta, rodando o script `instalador1.sh`:

```
./instalador1.sh
```
> Responder Sim/Yes para ambos prompts que surgir. Estas perguntas se referem a permitir a captura de pacotes como usuário comum. (Necessário)

Aguarde o término da instalação do `instalador1.sh` e execute o próximo comando.

```
newgrp docker && ./instalador2.sh
```

**Nota:** _No ambiente de desenvolvimento mencionado acima, o procedimento levou em média `11 minutos e 30 segundos` para concluir a instalação, baixando cerca de 2.3GB de dados pela internet e resultando no uso de 12GB de espaço adicional em disco._

Concluída a instalação, a ferramenta estará disponível acessando http://endereço.ip.da.instalação:8501/ ou http://127.0.0.1:8501/ (caso o local da instalação possua um Web Browser).

### Parar ou iniciar os servidores (pós conclusão da instalação, caso deseje):

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