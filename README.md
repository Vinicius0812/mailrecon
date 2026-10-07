# MailRecon

[Versão em inglês](READMEeng.md)

CLI em Python para OSINT ético, validação técnica de e-mails e investigação defensiva autorizada. Organiza entradas, hipóteses e evidências públicas para revisão humana. Não confirma a identidade de uma pessoa nem a existência de uma caixa postal individual.

## Artefatos offline

```bash
mailrecon sources
mailrecon demo --output-dir reports
mailrecon --language en demo --output-dir reports/demo-en
mailrecon search-links "Pessoa Ficticia" --organization "Synthetic Example" --domain example.com --context "pesquisa autorizada" --after 2026-01-01 --before 2026-10-07 --file-type pdf
```

`sources` inspeciona o catálogo próprio: GitHub/GitLab têm regras de API oficial opcionais; as demais fontes são somente pivôs manuais. Não consulta a rede. Mostra documentação ou URL do pivô, método e versão da regra.

`demo` gera nove arquivos determinísticos: `demo-recon`, `demo-investigation` e `demo-smtp`, cada um em JSON, Markdown e HTML. Todos os dados são sintéticos e identificados como tal. Não faz DNS/HTTP/HIBP/SMTP e não lê/grava refinamento ou configuração. O diretório deve ser separado dos caminhos de estado sensíveis; arquivos existentes não são sobrescritos. `reports/` é ignorado pelo Git. Para QA, abra `reports/demo-investigation.html` diretamente no navegador; não é necessário servidor.

`search-links` é separado da investigação e não altera seu fingerprint nem estados antigos. Apenas compõe links Google com `urlencode`, sem scraping, consulta ou abertura automática do navegador. Os termos de organização/contexto são literais; `--domain` gera um link por domínio. Datas ISO válidas, não invertidas, e tipos `pdf`, `docx`, `xlsx`, `pptx`, `txt` são opcionais. Os operadores são sugestões ao buscador: não garantem data, tipo ou cobertura. **Links gerados não são achados nem evidências.** E-mails são mascarados também dentro da query codificada; `--reveal-emails` é necessário para gerar links com o endereço completo.

## Relatório HTML local

```bash
mailrecon analyze pessoa@example.com --no-hibp --html-out reports/analysis.html
mailrecon investigate --username demo-example --no-hibp --html-out reports/investigation.html
mailrecon interactive --html-out reports/interactive.html
mailrecon rerun-last --no-hibp --html-out reports/rerun.html
mailrecon lab-admin --handle demo-example --html-out reports/lab.html
mailrecon lab-smtp-validate pessoa@lab.local --lab-domain lab.local --no-network --html-out reports/smtp.html
```

Os comandos acima mantêm sua política de rede normal; somente `demo`, `sources` e `search-links` são totalmente offline. `--no-hibp` não desabilita DNS. `lab-admin` pode fazer DNS quando recebe domínio/e-mail.

HTML é arquivo estático, com tabelas roláveis, filtro textual e seleção de hipótese/observado/sintético. Exibe fontes, método, escopo de confiança, regra/versão e timestamp quando disponíveis; resultados nunca confirmam identidade. O idioma segue `--language`; `--markdown-language` continua específico do Markdown. HTML, terminal e Markdown mascaram e-mails por padrão; `--reveal-emails` revela essas saídas. JSON mantém dados completos e deve ser protegido.

Evidências HIBP incluem `collection_performed` (booleano opcional): disabled/chave ausente não representam coleta; consultas negativas ou inconclusivas podem ser observadas. Registros antigos sem esse metadado são tratados conservadoramente como hipótese para HIBP. O renderer não interpreta prosa para decidir coleta. Literais percent/entity sem e-mail ou controle oculto são preservados; a decodificação de privacidade é aplicada somente quando necessária.

Dados são escapados, controles neutralizados e URLs com e-mails completos são removidas dos hyperlinks no modo mascarado, inclusive encoding aninhado. Só links http(s) sem credenciais podem ser clicados, com `noopener noreferrer` e política de referrer. Não há JSON bruto embutido, servidor, CDN, fontes, imagens remotas ou rastreadores. CSP autoriza somente os hashes do CSS/JS próprios; filtros leem `textContent`, nunca inserem dados com `innerHTML`. Abrir um hyperlink é uma ação manual de rede do usuário. Mascaramento não equivale a anonimização: domínio, usuário e contexto podem continuar identificáveis.

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
- JSON, Markdown e HTML offline; pt-BR padrão e inglês opcional; mascaramento nas saídas humanas.

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

`rerun-last` reutiliza as opções salvas, inclusive HIBP; `rerun-last --no-hibp` pode desabilitar HIBP, nunca habilitá-lo se estava desabilitado. `--check-public-profiles` faz checagens opcionais somente nas duas APIs oficiais descritas abaixo. Bloqueio, login, limite de requisições ou erro não provam ausência de uma conta.

### Catálogo e rede de perfis

O catálogo tipado e validado é próprio do MailRecon. GitHub usa `GET https://api.github.com/users/{handle}` ([documentação oficial](https://docs.github.com/en/rest/users/users#get-a-user)); GitLab usa `GET https://gitlab.com/api/v4/users?username={handle}` ([documentação oficial](https://docs.gitlab.com/api/users/)). Apenas o usuário exato fornecido/derivado é consultado: sem busca por e-mail, listagem geral ou paginação. LinkedIn, Instagram, Facebook, X, Spotify, Telegram e Gravatar permanecem pivôs manuais, sem HTTP automático. URLs de busca são sugestões manuais, nunca consultadas pelo verificador.

Os pedidos não têm autenticação, cookies persistentes, proxies do ambiente, rotação de User-Agent, retries ou redirecionamentos automáticos. O User-Agent é `MailRecon/0.1`. Origem, usuário e URL canônica do pivô são validados antes de rede; o endpoint é construído exclusivamente pelo catálogo. A leitura por streaming limita bytes; respostas comprimidas inesperadas são inconclusivas. Orçamentos limitam pedidos por investigação e por fonte; 401/403/429 desabilitam essa fonte até a próxima execução. Limites esgotados e fontes manuais permanecem `not_checked`.

HTTP 200 exige JSON esperado, ID inteiro positivo, usuário exatamente correspondente pela semântica case-insensitive de GitHub/GitLab e URL oficial canônica correspondente. Apenas o handle é comparado com `casefold`; a URL deve ser exatamente a construída pelo catálogo com o handle retornado validado, sem relaxar host, path, encoding, query ou fragmento. HTML, soft-404/login, corpo genérico/malformado ou divergente são `ambiguous`, nunca evidência positiva. GitLab com array vazio é `not_found`; múltiplos registros são ambíguos. 404 de GitHub é ausência de perfil público retornado, não prova de inexistência de conta; 404 de GitLab é inconclusivo. `rule_id`, `rule_version`, `check_method` e `cache_hit` permitem rastrear a regra.

O cache é limitado, apenas em memória e por instância do serviço, não persistente. Guarda somente classificação sanitizada de resultados positivos/negativos, sem corpo bruto, e expira por TTL monotônico. Reuso não consome orçamento nem renova o TTL; `checked_at` e `collected_at` conservam a hora da observação original. Cada investigação reseta orçamento/bloqueios, mas pode reutilizar o cache vivo da mesma instância; novos processos não compartilham cache. TTL ou capacidade zero desabilita cache.

## Confiança e proveniência

A deduplicação mantém a origem principal em `source`, nesta ordem:

1. `seed_email`: e-mail informado diretamente.
2. `provided_candidate`: candidato informado explicitamente.
3. `username_domain_inference`: hipótese por usuário e domínio.
4. `name_domain_inference`: hipótese por nome e domínio.

`sources` preserva todas as origens. Uma inferência não substitui a entrada direta.

`confidence_scope` identifica a afirmação avaliada. Entrada direta ou explícita tem confiança `medium` (média) na informação fornecida; inferências têm `low` (baixa) na hipótese. Formato inválido, NXDOMAIN e Null MX recebem baixa. DNS não eleva confiança de identidade.

Perfil público confirmado pela regra de API tem confiança média apenas em `public_profile_existence`, não na titularidade ou correspondência com o e-mail. Sucesso HTTP genérico nunca recebe média. Não verificado, ambíguo, bloqueado, ausente ou com erro ficam com baixa. Simulações têm escopo sintético e não observam uma plataforma real; não entram no breakdown real. Correlação de identidade permanece zero.

HIBP tem confiança média no registro de exposição apenas em `breaches_found`. Consulta desabilitada, chave ausente, negativa ou falha recebem baixa. Ausência de vazamentos conhecidos não prova segurança, inatividade ou inexistência.

`review_priority_score` é uma **heurística de triagem**, não probabilidade ou percentual de acerto. Zero permanece zero; pontuações antigas não substituem esse campo. Tetos conservadores: direto 70, explícito 60, inferência por usuário 45 e por nome 30; conta funcional 35, domínio descartável 25, perfil alcançável 45 (sem aumento automático da pontuação inicial). Penalidades reduzem a prioridade em investigações ruidosas.

O detalhamento usa regras independentes para formato validado, observação DNS e checagens de perfil realmente realizadas. Correlação de identidade permanece zero sem evidência independente. Dados pessoais informados, DNS e padrões de URL não confirmam identidade. As pontuações não têm calibração estatística.

## Refinamento e privacidade

O estado fica em `.mailrecon-temp/last-investigation-refinement.json`. Adicione URLs refutadas manualmente a `excluded_profile_urls` e rode `mailrecon rerun-last`. Estados antigos continuam legíveis; a nova execução aplica o idioma selecionado.

Exclusões só são aplicadas quando o fingerprint corresponde à consulta e são filtradas antes das checagens de perfil, inclusive antes do cache. O estado nunca fornece destinos de HTTP: URLs sugeridas/arbitrárias do arquivo não criam pivôs; os destinos vêm apenas do catálogo. Candidatos inferidos por nome/usuário não são enviados ao HIBP por padrão; entradas diretas e candidatos explicitamente fornecidos mantêm a política atual. O serviço oferece `allow_inferred_hibp=True` somente para um escopo explicitamente autorizado, sem mutar o provider global. `ReconService.analyze_email(..., use_hibp=False)` omite o provider para uma chamada.

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

Compatibilidade de segurança: nomes de host na allowlist não são mais aceitos. `localhost` literal só é aceito no transporte `localhost` e conecta diretamente a `127.0.0.1`; esse transporte aceita apenas IPs loopback. `private-lab` exige IP literal RFC1918, IPv6 ULA ou loopback explicitamente listado em `MAILRECON_LAB_SMTP_ALLOW_HOSTS`. A allowlist nunca libera IP público, link-local, multicast, unspecified ou outras faixas especiais/de documentação. Não há resolução DNS do alvo; a conexão usa o IP classificado. Portas 25/465/587 permanecem bloqueadas fora de loopback, e `expn` permanece exclusivo de `localhost`. Transporte/host/domínio são normalizados antes da avaliação e execução; `mock` com espaços/maiúsculas e `--no-network` não abre conexão.

Respostas SMTP têm controles de terminal escapados nas saídas humanas (terminal/Markdown); o JSON mantém a resposta bruta decodificada. Erros do parser mascaram e-mails em ambos os idiomas, sem ocultar flags.

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
| `MAILRECON_PROFILE_TOTAL_BUDGET` | `20` | Pedidos de API por investigação, 0 a 100 |
| `MAILRECON_PROFILE_SOURCE_BUDGET` | `10` | Pedidos por fonte/execução, 0 a 50 |
| `MAILRECON_PROFILE_MAX_RESPONSE_BYTES` | `65536` | Bytes por resposta, 1024 a 1048576 |
| `MAILRECON_PROFILE_CACHE_TTL` | `60` | TTL em segundos, 0 a 300 |
| `MAILRECON_PROFILE_CACHE_ENTRIES` | `128` | Entradas em memória, 0 a 512 |

Limites devem ser inteiros dentro dos intervalos; valores inválidos usam o padrão. Orçamento zero desabilita novos pedidos de API. O timeout HTTP para perfis é limitado a 60 segundos, com fallback de 10 segundos para valor inválido.

Além do timeout por operação HTTP, há deadline monotônico da resposta inteira com o mesmo valor, contando conexão/headers e verificado em cada chunk bruto sem agregação e antes de classificar o corpo. Expiração interrompe a coleta, fecha a resposta e não cria cache. Em I/O síncrono, uma leitura já bloqueada só pode retornar pelo timeout de operação; o deadline não interrompe uma chamada bloqueada no sistema operacional.

## Arquitetura e testes

```text
src/mailrecon/
  cli/          comandos, perguntas e seleção de idioma
  core/         modelos, catálogos, validação, configuração e segurança
  services/     investigação, DNS, HIBP, perfis, refinamento e SMTP de laboratório
  reporting/    terminal e exportação JSON/Markdown/HTML
tests/          testes isolados, respostas simuladas e regressões
```

PowerShell:

```powershell
.\.venv\Scripts\python.exe scripts/run_offline_tests.py -q
.\.venv\Scripts\python.exe -m mailrecon.benchmark
git diff --check
```

Linux:

```bash
python scripts/run_offline_tests.py -q
python -m mailrecon.benchmark
git diff --check
```

Os testes usam simulações, sem consultar pessoas ou serviços reais. Cobrem proveniência, DNS/HTTP, confiança, pontuações, idiomas, mascaramento, exportação, refinamento e controles SMTP. Não substituem validação autorizada de integração nem demonstram acurácia estatística.

`scripts/run_offline_tests.py` bloqueia sockets de saída, DNS e SMTP real durante o pytest e desabilita `.env`. O benchmark próprio `mailrecon-owned-synthetic-api-v1` contém 21 fixtures positivas/negativas/ambíguas de GitHub/GitLab, incluindo generic 200, login, soft 404, handle/URL divergentes, bloqueio e rate limit. Precisão e falsos positivos dizem respeito **somente a essas fixtures**, nunca à acurácia real ou identidade.

A CI própria em `.github/workflows/tests.yml` configura Windows/Linux e Python 3.11/3.13, instalação editable dev, suíte offline, benchmark, build wheel/sdist e smoke do wheel instalado. Usa permissões `contents: read`, timeout de 15 minutos, sem segredos e checkout sem credenciais persistidas. As Actions foram verificadas nas releases oficiais: [checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) e [setup-python v7.0.0](https://github.com/actions/setup-python/releases/tag/v7.0.0), fixadas por SHA. Configuração de CI não significa execução remota validada. Localmente, build requer `build`, `wheel` e `setuptools>=68`; depois execute `python -m build --no-isolation` e `python scripts/package_smoke.py`.

O [relatório noturno](docs/RELATORIO-NOTURNO-2026-10-07.md) registra testes, limitações e pendências de revisão/publicação. Não foi encontrada licença declarada no repositório; nenhuma licença foi escolhida neste trabalho.

## Próximos passos

Para v0.2.0: regressões verdes, instalação validada em Windows/Linux, exemplos sintéticos revisados, limites de privacidade e compatibilidade JSON verificados. Evoluções devem priorizar evidências independentes autorizadas, rastreabilidade e menor ambiguidade, sem ampliar coleta intrusiva.
