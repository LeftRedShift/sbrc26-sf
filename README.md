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

#### Estando no diretório raiz deste repositório, tornar executável o script `installer.sh`::

```
chmod +x installer.sh
```

#### Construir **todas as imagens**, subir os servidores e disponibilizar o acesso à ferramenta, rodando o script `installer.sh`:

```
./installer.sh
```

> Aguarde o término da instalação. No ambiente de desenvolvimento mencionado acima, o procedimento levou em média `3 minutos e 30 segundos`.

### Parar ou iniciar os servidores (pós conclusão da instalação):

#### Estando no diretório raiz deste repositório, tornar executável o script `servers.sh`::

```
chmod +x servers.sh
```

#### Parar e remover os contêiners dos servidores:

```
./servers.sh parar
```

#### Iniciar os contêiners dos servidores:

```
./servers.sh iniciar
```