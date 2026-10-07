# MailRecon

[Versão em inglês](READMEeng.md)

CLI em Python para OSINT ético, validação técnica de e-mails e investigação defensiva autorizada. Organiza entradas, hipóteses e evidências públicas para revisão humana. Não confirma a identidade de uma pessoa nem a existência de uma caixa postal individual.

## Escopo

Projeto de portfólio para estudantes de segurança, analistas defensivos e investigadores com autorização. Usa validação de formato, DNS público e, opcionalmente, a API documentada do Have I Been Pwned (HIBP). Pode verificar páginas públicas já sugeridas, sem login.

Não automatiza login, recuperação de conta, testes de credenciais, enumeração abusiva ou coleta de dados privados. SMTP é isolado em laboratório, sem descoberta por MX e fora do fluxo normal. Use apenas dados próprios, fictícios ou de um escopo expressamente autorizado.

## Funcionalidades

- `analyze`: formato, DNS (A, AAAA, MX, NS, TXT), SPF, DMARC, família de provedor e HIBP opcional.
- `investigate`: entradas por nome, e-mail, usuário, domínio, organização, contexto e candidatos explícitos; proveniência, motivos e limitações.
- `interactive`: perguntas guiadas e escolha de exportações.
- `rerun-last`: reutiliza a investigação salva e suas exclusões manuais.
- `lab-admin`: simula estados de perfis sem acessar as plataformas.
- `lab-smtp-validate`: simulação SMTP ou checagens limitadas em laboratório configurado.
- JSON e Markdown; pt-BR padrão e inglês opcional; mascaramento nas saídas humanas da análise/investigação.

## Instalação

Requisitos: Python 3.11+, Git e rede para instalar dependências. HIBP é opcional e requer chave com acesso à API.

### Windows / PowerShell

```powershell
git clone https://github.com/Vinicius0812/mailrecon.git
cd mailrecon
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
Copy-Item .env.example .env
.\.venv\Scripts\mailrecon.exe --help
.\.venv\Scripts\mailrecon.exe analyze pessoa@example.com --no-hibp
```

Não é necessário ativar o ambiente. Para habilitar HIBP na sessão:

```powershell
$env:HIBP_API_KEY = "SUA_CHAVE"
.\.venv\Scripts\mailrecon.exe analyze pessoa@example.com
```

### Linux / shell

```bash
git clone https://github.com/Vinicius0812/mailrecon.git
cd mailrecon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
mailrecon --help
mailrecon analyze pessoa@example.com --no-hibp
export HIBP_API_KEY='SUA_CHAVE'
```

Os endereços em `example.com` são fictícios; seu DNS real não representa um laboratório de caixas postais.

## Idiomas e comandos

`--language pt-br|en` é global: coloque **antes do subcomando**. Comandos, flags, chaves JSON e valores técnicos como `low`, `medium` e estados permanecem em inglês. Rótulos e níveis de confiança nas saídas humanas são traduzidos.

Os exemplos abaixo pressupõem ambiente ativado. No PowerShell sem ativação, use o caminho do executável mostrado acima.

```bash
mailrecon --language pt-br analyze pessoa@example.com --no-hibp
mailrecon --language en investigate --email pessoa@example.com --username pessoa --domain example.com --no-hibp
mailrecon investigate --name "Pessoa Exemplo" --email pessoa@example.com --candidate-email pessoa@example.com --domain example.com --no-hibp --json-out reports/investigacao.json --md-out reports/investigacao.md
mailrecon --language pt-br analyze pessoa@example.com --no-hibp --md-out reports/analysis-en.md --markdown-language en
mailrecon interactive --no-hibp
mailrecon --language en rerun-last
```

O Markdown herda o idioma do terminal. `--markdown-language pt-br|en` altera apenas o relatório e está disponível em todos os comandos com exportação Markdown. No interativo em português, use `s`/`sim` ou `n`/`não`/`nao`; em inglês, `y`/`yes` ou `n`/`no`. Enter aplica o padrão anunciado.

`rerun-last` reutiliza as opções salvas, inclusive HIBP; não aceita uma nova flag `--no-hibp`. `--check-public-profiles` faz checagens HTTP públicas opcionais. Bloqueio, login, limite de requisições ou erro não provam ausência de uma conta.

## Confiança e proveniência

A deduplicação mantém a origem principal em `source`, nesta ordem:

1. `seed_email`: e-mail informado diretamente.
2. `provided_candidate`: candidato informado explicitamente.
3. `username_domain_inference`: hipótese por usuário e domínio.
4. `name_domain_inference`: hipótese por nome e domínio.

`sources` preserva todas as origens. Uma inferência não substitui a entrada direta.

`confidence_scope` identifica a afirmação avaliada. Entrada direta ou explícita tem confiança `medium` (média) na informação fornecida; inferências têm `low` (baixa) na hipótese. Formato inválido, NXDOMAIN e Null MX recebem baixa. DNS não eleva confiança de identidade.

Página alcançável tem confiança média apenas no alcance HTTP, não na titularidade ou correspondência com o e-mail. Não verificado, ambíguo, bloqueado, ausente ou com erro ficam com baixa. Simulações têm escopo sintético e não observam uma plataforma real.

HIBP tem confiança média no registro de exposição apenas em `breaches_found`. Consulta desabilitada, chave ausente, negativa ou falha recebem baixa. Ausência de vazamentos conhecidos não prova segurança, inatividade ou inexistência.

`review_priority_score` é uma **heurística de triagem**, não probabilidade ou percentual de acerto. Zero permanece zero; pontuações antigas não substituem esse campo. Tetos conservadores: direto 70, explícito 60, inferência por usuário 45 e por nome 30; conta funcional 35, domínio descartável 25, perfil alcançável 45 (sem aumento automático da pontuação inicial). Penalidades reduzem a prioridade em investigações ruidosas.

O detalhamento usa regras independentes para formato validado, observação DNS e checagens de perfil realmente realizadas. Correlação de identidade permanece zero sem evidência independente. Dados pessoais informados, DNS e padrões de URL não confirmam identidade. As pontuações não têm calibração estatística.

## Refinamento e privacidade

O estado fica em `.mailrecon-temp/last-investigation-refinement.json`. Adicione URLs refutadas manualmente a `excluded_profile_urls` e rode `mailrecon rerun-last`. Estados antigos continuam legíveis; a nova execução aplica o idioma selecionado.

**JSON e estado de refinamento contêm dados completos**, inclusive e-mails, nomes, contextos e URLs. Mascaramento não anonimiza esses arquivos. Não publique relatórios reais, chaves ou estados locais. Restrinja acesso e retenção conforme o escopo autorizado. `--reveal-emails` revela e-mails na análise/investigação; saídas humanas de SMTP também são mascaradas, mas seu JSON mantém o endereço informado.

Mensagens do projeto conservam chave e parâmetros em metadados opcionais `localization` no JSON. O mesmo resultado pode ser renderizado em outro idioma sem novas consultas. Entradas, URLs, respostas externas e identificadores técnicos são preservados.

## Laboratórios

Perfil sintético sem acesso às plataformas:

```bash
mailrecon lab-admin --handle usuario_ficticio --scenario found --md-out reports/lab.md
mailrecon lab-admin --handle usuario_ficticio --scenario blocked
```

Não forneça domínio ou e-mail se quiser evitar também coleta DNS. Cenários: `found`, `not-found`, `ambiguous`, `blocked`, `rate-limited`.

SMTP sem rede:

```bash
mailrecon lab-smtp-validate pessoa@lab.local --lab-domain lab.local --transport mock --no-network --check vrfy --md-out reports/smtp.md
```

Rede SMTP exige `MAILRECON_ENABLE_LAB_SMTP=1`, `--confirm-lab-only`, host e domínio explícitos compatíveis e transporte `localhost` ou `private-lab`. Padrão: `mock`, até três sondagens (`vrfy`, `rcpt`, `expn`). Não use serviços públicos ou alvos sem autorização. Respostas não provam existência ou controle de caixas postais reais.

## Configuração

Veja [.env.example](.env.example).

| Variável | Padrão | Uso |
| --- | --- | --- |
| `HIBP_API_KEY` | vazio | HIBP opcional |
| `MAILRECON_HTTP_TIMEOUT` | `10.0` | Limite HTTP, em segundos |
| `MAILRECON_DNS_TIMEOUT` | `5.0` | Limite DNS, em segundos |
| `MAILRECON_ENABLE_LAB_SMTP` | `0` | Habilitação de SMTP com rede |
| `MAILRECON_LAB_SMTP_ALLOW_HOSTS` | vazio | Hosts permitidos do laboratório |
| `MAILRECON_LAB_SMTP_TIMEOUT` | `3.0` | Limite SMTP, em segundos |

## Arquitetura e testes

```text
src/mailrecon/
  cli/          comandos, perguntas e seleção de idioma
  core/         modelos, catálogos, validação, configuração e segurança
  services/     investigação, DNS, HIBP, perfis, refinamento e SMTP de laboratório
  reporting/    terminal e exportação JSON/Markdown
tests/          testes isolados, respostas simuladas e regressões
```

PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
git diff --check
```

Linux:

```bash
python -m pytest -q
git diff --check
```

Os testes usam simulações, sem consultar pessoas ou serviços reais. Cobrem proveniência, DNS/HTTP, confiança, pontuações, idiomas, mascaramento, exportação, refinamento e controles SMTP. Não substituem validação autorizada de integração nem demonstram acurácia estatística.

## Próximos passos

Para v0.2.0: regressões verdes, instalação validada em Windows/Linux, exemplos sintéticos revisados, limites de privacidade e compatibilidade JSON verificados. Evoluções devem priorizar evidências independentes autorizadas, rastreabilidade e menor ambiguidade, sem ampliar coleta intrusiva.
