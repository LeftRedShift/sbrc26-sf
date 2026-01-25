# sbrc26-sf - Salão de Ferramentas SBRC 2026

### Ambiente de desenvolvimento (apenas para referência):
- Sistema Operacional Host: Kubuntu Desktop 24.04 LTS
- Processador AMD Ryzen 5 5600X
- 32 GB de RAM
- GPU GeForce RTX 3070Ti com 8 GB de VRAM
- 1TB de armazenamento
- Internet 500Mbps de download / 50Mbps de upload

### Ambiente e configurações mínimas para execução:
- Sistema Operacional baseado em Ubuntu 24.04 LTS
- Processador baseado em arquitetura x86/AMD64
- 8 GB de RAM
- 15GB de espaço disponível
- Acesso à internet

### Instalação automatizada:

#### Estando no diretório raiz deste repositório, tornar executável o script `instalador.sh`::

```
chmod +x instalador.sh
```

#### Construir **todas as imagens**, subir os servidores e disponibilizar o acesso à ferramenta, rodando o script `instalador.sh`:

```
./instalador.sh
```

> Aguarde o término da instalação. No ambiente de desenvolvimento mencionado acima, o procedimento levou em média `3 minutos e 30 segundos`.

### Parar ou iniciar os servidores (pós conclusão da instalação):

#### Estando no diretório raiz deste repositório, tornar executável o script `servidores.sh`::

```
chmod +x servidores.sh
```

#### Parar e remover os contêiners dos servidores:

```
./servidores.sh parar
```

#### Iniciar os contêiners dos servidores:

```
./servidores.sh iniciar
```

### Parar ou iniciar os clientes "benignos" (pós conclusão da instalação):

#### Estando no diretório raiz deste repositório, tornar executável o script `clientes.sh`::

```
chmod +x clientes.sh
```

#### Parar e remover os contêiners dos clientes:

```
./clientes.sh parar
```

#### Iniciar um cliente:

```
./clientes.sh iniciar
```
> O comando `./clientes.sh iniciar` inicia mais um container cliente, independente de quantos já estejam rodando.