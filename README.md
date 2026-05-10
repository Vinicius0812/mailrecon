# MailRecon

MailRecon is an educational Python CLI for email recon and validation using public sources, permitted integrations, and study-friendly workflows.

MailRecon é uma CLI educacional em Python para recon e validação de e-mails usando fontes públicas, integrações permitidas e um fluxo amigável para estudo.

The project is intentionally small, ethical, and suitable for a beginner cybersecurity portfolio. Its main goal is to help study Python CLI architecture, modular design, API integrations, error handling, reporting, and tests without becoming a large framework.

O projeto é intencionalmente pequeno, ético e adequado para portfólio de cibersegurança em nível iniciante. O objetivo principal é estudar arquitetura de CLI em Python, organização modular, integrações com API, tratamento de erros, relatórios e testes sem virar um framework grande.

## Goals | Objetivos

- Validate an email address | Validar um endereço de e-mail
- Extract and inspect the domain | Extrair e inspecionar o domínio
- Query DNS and MX records | Consultar registros DNS e MX
- Optionally query Have I Been Pwned | Consultar opcionalmente o Have I Been Pwned
- Show a friendly terminal summary | Mostrar um resumo amigável no terminal
- Export reports as JSON and Markdown | Exportar relatórios em JSON e Markdown

## Ethical Scope | Escopo Ético

MailRecon is designed for:

MailRecon foi pensado para:

- educational environments | ambientes educacionais
- authorized labs | laboratórios autorizados
- portfolio projects | projetos de portfólio
- validation against public sources and documented APIs | validação com fontes públicas e APIs documentadas

It does not aim to perform intrusive validation, SMTP abuse, or unauthorized enumeration.

Ele não tem como objetivo realizar validação intrusiva, abuso de SMTP ou enumeração não autorizada.

## Why This Project | Por Que Este Projeto

This project was created as a beginner-friendly cybersecurity portfolio piece focused on ethical recon, defensive curiosity, and public-source validation. It aims to be small enough to finish, clear enough to study, and structured enough to grow over time.

Este projeto foi criado como uma peça de portfólio de cibersegurança em nível iniciante, com foco em recon ético, curiosidade defensiva e validação com fontes públicas. A proposta é ser pequeno o bastante para ser concluído, claro o bastante para estudo e organizado o bastante para evoluir com o tempo.

## Stack

- Python 3.11+
- Typer for the CLI | Typer para a CLI
- httpx for HTTP calls | httpx para chamadas HTTP
- email-validator for email validation | email-validator para validação de e-mail
- dnspython for DNS and MX lookups | dnspython para consultas DNS e MX
- python-dotenv for environment configuration | python-dotenv para configuração por ambiente
- pytest for basic tests | pytest para testes básicos

## Project Structure | Estrutura do Projeto

```text
mailrecon/
├── .env.example
├── .gitignore
├── README.md
├── pyproject.toml
├── src/
│   └── mailrecon/
│       ├── __init__.py
│       ├── main.py
│       ├── cli/
│       │   ├── __init__.py
│       │   └── app.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py
│       │   ├── models.py
│       │   └── validators.py
│       ├── services/
│       │   ├── __init__.py
│       │   ├── dns_service.py
│       │   ├── hibp_service.py
│       │   └── recon_service.py
│       └── reporting/
│           ├── __init__.py
│           ├── console.py
│           └── exporters.py
└── tests/
    ├── __init__.py
    ├── test_cli.py
    ├── test_dns_service.py
    ├── test_exporters.py
    ├── test_hibp_service.py
    └── test_validators.py
```

## MVP Scope | Escopo do MVP

The first version focuses on a single command:

A primeira versão foca em um único comando:

```bash
mailrecon analyze user@example.com
```

Features included in the MVP:

Funcionalidades incluídas no MVP:

- email format validation | validação de formato de e-mail
- domain extraction | extração de domínio
- DNS and MX lookup | consulta DNS e MX
- domain resolution check | verificação se o domínio resolve
- HIBP integration prepared through environment variables | integração com HIBP preparada via variáveis de ambiente
- JSON and Markdown export | exportação em JSON e Markdown
- friendly terminal output | saída amigável no terminal
- basic tests | testes básicos

## Roadmap | Roadmap

### MVP

- end-to-end `analyze` command | comando `analyze` de ponta a ponta
- JSON and Markdown reporting | relatórios em JSON e Markdown
- tests and documentation | testes e documentação

### v1.1

- better terminal output | saída melhor no terminal
- stronger error handling | tratamento de erros mais robusto
- configurable behavior and richer docs | comportamento configurável e documentação mais rica

### v1.2

- optional interactive mode | modo interativo opcional
- batch processing | processamento em lote
- more DNS-focused enrichment | enriquecimento adicional focado em DNS

## Learning Outcomes | Aprendizados

This project is meant to support hands-on learning in:

Este projeto foi pensado para apoiar aprendizado prático em:

- Python CLI design | design de CLI em Python
- modular project structure | estrutura modular de projeto
- external API integration | integração com APIs externas
- environment-based configuration | configuração por variáveis de ambiente
- resilient error handling | tratamento resiliente de erros
- JSON and Markdown reporting | geração de relatórios em JSON e Markdown
- basic automated tests | testes automatizados básicos

## Prerequisites | Pré-requisitos

You need the following programs installed before running the project.

Você precisa dos programas abaixo instalados antes de executar o projeto.

### Windows

- Python 3.11 or newer | Python 3.11 ou mais recente
- `pip` for Python package installation | `pip` para instalação de pacotes Python
- PowerShell or Windows Terminal | PowerShell ou Windows Terminal
- Git

Recommended checks:

Comandos recomendados para verificar:

```powershell
python --version
pip --version
git --version
```

If `python` is not available, try:

Se `python` não estiver disponível, tente:

```powershell
py --version
```

### Linux

- Python 3.11 or newer | Python 3.11 ou mais recente
- `pip`
- `venv` support for virtual environments | suporte a `venv` para ambientes virtuais
- Git

Recommended checks:

Comandos recomendados para verificar:

```bash
python3 --version
pip3 --version
git --version
```

On Debian, Ubuntu, or Kali, you usually need:

Em Debian, Ubuntu ou Kali, normalmente você vai precisar de:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
```

## Installation | Instalação

Before running the installation commands, clone the repository and enter the project folder.

Antes de executar os comandos de instalação, clone o repositório e entre na pasta do projeto.

### Windows

```powershell
git clone https://github.com/Vinicius0812/mailrecon.git
cd mailrecon
python -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
```

If your system uses the Python launcher:

Se o seu sistema usa o Python Launcher:

```powershell
git clone https://github.com/Vinicius0812/mailrecon.git
cd mailrecon
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -e .[dev]
```

### Linux

```bash
git clone https://github.com/Vinicius0812/mailrecon.git
cd mailrecon
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### What These Commands Do | O Que Esses Comandos Fazem

- `git clone https://github.com/Vinicius0812/mailrecon.git`: downloads the repository | baixa o repositório
- `cd mailrecon`: enters the project folder | entra na pasta do projeto
- creates the virtual environment | cria o ambiente virtual
- activates the virtual environment | ativa o ambiente virtual
- installs the project and development dependencies | instala o projeto e as dependências de desenvolvimento

## Usage | Uso

Run the main analysis command:

Execute o comando principal de análise:

```bash
mailrecon analyze user@example.com
```

Export reports when needed:

Exporte relatórios quando precisar:

```bash
mailrecon analyze user@example.com --json-out reports/result.json --md-out reports/result.md
```

Disable the HIBP request explicitly:

Desabilite a consulta ao HIBP explicitamente:

```bash
mailrecon analyze user@example.com --no-hibp
```

## Environment Variables | Variáveis de Ambiente

Copy `.env.example` to `.env` and fill the values you want to use:

Copie `.env.example` para `.env` e preencha os valores que quiser usar:

```env
HIBP_API_KEY=
MAILRECON_HTTP_TIMEOUT=10.0
MAILRECON_DNS_TIMEOUT=5.0
```

## Development Notes | Notas de Desenvolvimento

- Keep the CLI thin | Mantenha a CLI fina
- Keep integrations inside `services` | Mantenha as integrações em `services`
- Keep validation and models inside `core` | Mantenha validação e modelos em `core`
- Keep output logic inside `reporting` | Mantenha a lógica de saída em `reporting`

This separation makes the project easier to study and easier to expand later with new commands or an interactive mode.

Essa separação deixa o projeto mais fácil de estudar e mais fácil de expandir depois com novos comandos ou um modo interativo.
