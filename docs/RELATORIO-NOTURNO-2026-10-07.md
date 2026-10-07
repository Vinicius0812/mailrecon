# Relatório Noturno MailRecon - 2026-10-07

## Estado da entrega

Implementação defensiva em três etapas, diretamente na raiz compartilhada, branch `codex/mailrecon-precision`. Etapas 1 e 2 foram aceitas e commitadas pelo coordenador. Implementação funcional da etapa 3 aceita pelo coordenador após repetição do QA de navegador; revisão final Blue permanece como gate de publicação. Sem commit/push pelo executor. Publicação ainda pendente.

Não foram usados código, listas ou assets do Mr.Holmes, dados reais, credenciais, login, recuperação de senha, enumeração de contas, coleta privada ou evasão. Este executor não criou outros agentes; o coordenador utilizou executor e revisor para implementação e revisão independente. As suítes offline finais desabilitam Dotenv explicitamente e bloqueiam SMTP/DNS/HTTP/HIBP reais; as demonstrações são sintéticas e não consultam esses serviços. Não se afirma ausência de importação/carregamento do loader normal no baseline do coordenador. Nenhuma credencial foi publicada. A navegação externa deste executor foi restrita à verificação de documentação pública oficial.

## Etapas e extras

1. **SMTP e segurança:** normalização única de transporte/host/domínio; mock com whitespace/case sem rede; allowlist restritiva, não autorizadora de IP público; conexão ao IP previamente classificado. `localhost` literal fixa loopback, `private-lab` exige IP literal permitido, sem resolução DNS. Gates de ambiente/confirmação, portas e limites de sondagens preservados. Controles de terminal neutralizados e e-mails mascarados nos erros do parser pt-BR/en sem ocultar flags.
2. **Catálogo, precisão e privacidade:** catálogo próprio tipado e validado, GitLab incluído. Somente GitHub/GitLab possuem regras automatizadas de username exato. Payload genérico, login/soft 404, handle/URL divergentes e corpos malformados são inconclusivos, não positivos. Correspondência lógica case-insensitive com URL canônica estrita. Confiança se refere a existência de perfil público, nunca identidade; correlação de identidade permanece zero. Fontes restantes são somente manuais.
3. **Limites e privacidade adicionais:** orçamento por investigação/fonte, máximo de bytes, streaming bruto sem agregação, deadline monotônico da resposta inteira, sem retries/redirects/proxy do ambiente. Bloqueio/429 desabilita a fonte pelo resto da execução. Cache sanitizado em memória com TTL/capacidade, timestamp original, `cache_hit` e prioridade reconstruída do pivô atual (inclusive zero); orçamento reinicia por execução. HIBP omitido por padrão para candidatos inferidos; entradas diretas/explicitamente fornecidas mantêm a política existente. `rerun-last --no-hibp` só reduz consultas. Exclusões por fingerprint aplicadas antes do HTTP/cache; arquivo de estado não introduz URLs executáveis arbitrárias.
4. **Artefatos e buscas manuais:** HTML estático próprio para Recon, Investigation e SMTP, integrado por `--html-out` nos seis comandos de relatório. Tabelas roláveis e filtros por texto/estado, pt-BR/en, proveniência, escopo, método e versão de regra. Escapamento de dados, links http(s) sem credenciais, proteção de e-mails também em href codificado, CSP restritiva com hashes, sem JSON bruto/CDN/recursos remotos. `sources`, `demo` e `search-links` são offline; demo não grava refinamento. Filtros opcionais de data ISO e tipo de arquivo são validados; links nunca são achados.
5. **Demonstração e CI:** nove artefatos sintéticos por idioma, diretório validado sem sobrescrita. Benchmark próprio reproduzível com 21 fixtures de APIs. CI própria Windows/Linux, Python 3.11/3.13, testes com guard de rede, build wheel/sdist e smoke de pacote instalado, permissões mínimas, timeout e sem segredos. Actions oficiais verificadas e fixadas por SHA; nenhum workflow de terceiro foi copiado.

## Verificação

| Marco | Testes aprovados |
| --- | ---: |
| Baseline | 455 |
| Etapa 1: SMTP/parser/allowlist | 523 |
| Etapa 2: APIs/catálogo/privacidade | 706 |
| Etapa 3: primeiro subbloco HTML | 721 |
| Etapa 3: buscas/demo offline | 745 |
| Etapa 3: suíte final após feedback HTML | 777 |
| Etapa 3: ajuste visual de tabelas/título | 783 |

Suíte final executada em **Windows, Python 3.11.9**, usando `python scripts/run_offline_tests.py -q`: saída de rede, DNS e SMTP real bloqueados, `.env` desabilitado. `git diff --check` aprovado em cada subbloco. Os avisos locais LF/CRLF não são erros de whitespace.

O benchmark `python -m mailrecon.benchmark` reproduziu 21/21 classificações esperadas, 2 verdadeiros positivos, 0 falsos positivos, 0 falsos negativos e precisão 1,0 **somente nesse conjunto sintético**. Inclui negativos e ambiguidades, login, generic 200, soft 404, id inválido, handle/URL divergentes, bloqueio, 429 e múltiplas correspondências GitLab. Não mede acurácia real, cobertura de plataformas ou identidade.

O coordenador informou revisão de diff e repetição de 126 testes críticos após a etapa 1 e 136 testes de APIs/privacidade após a etapa 2. A revisão independente da fase 1 cobriu 73 casos, sem findings. Isso não equivale à revisão independente final da etapa 3, ainda pendente da revisão blue.

QA adicional informado pelo coordenador: suíte completa offline com 777 testes aprovados; tooling instalado somente em `.venv` (`build` 1.6.1, `wheel` 0.48, `setuptools` 84). `python -m build --no-isolation` aprovado, gerando sdist e wheel 0.1.0. `scripts/package_smoke.py` aprovado com instalação do wheel em diretório temporário e validação de `sources`, `demo` e entrypoint. Nenhuma dependência de runtime foi alterada.

Browser QA do coordenador com Playwright/Chrome em pt-BR/en, viewports 1280x900 e 390x844: sem erros JS, requisições remotas ou overflow do body; filtro de 36 para 0 registros e reset para 36; labels associados aos controles. Screenshots em `reports/browser-qa/*.png`. Feedback visual aplicado depois desse QA: tabelas de duas colunas recebem classe `compact`, largura mínima zero, layout fixo, colunas responsivas e wrapping; tabelas largas mantêm scroll horizontal. H1/title passam a usar só o título já traduzido, sem duplicar MailRecon.

Repetição pós-ajuste concluída e aprovada pelo coordenador nas 12 combinações: Recon/Investigation/SMTP × pt-BR/en × desktop 1280x900/mobile 390x844. Filtros/reset aprovados; nas demonstrações sintéticas, o filtro observado retorna zero. Sem erros JS, requisições HTTP ou overflow da página; tabelas compactas cabem no viewport. Esse resultado fundamenta o aceite funcional da fase 3, sem presumir aprovação Blue, execução de CI remota ou publicação.

## Arquivos e QA

Principais arquivos novos: `src/mailrecon/reporting/html.py`, `src/mailrecon/cli/offline.py`, `src/mailrecon/services/search_links_service.py`, `src/mailrecon/services/demo_service.py`, `src/mailrecon/benchmark.py`, `scripts/run_offline_tests.py`, `scripts/package_smoke.py`, `.github/workflows/tests.yml` e testes correspondentes. Integrações em `cli/app.py`, catálogos de tradução e ambos os READMEs. Configuração da etapa 2 continua documentada em `.env.example`, sem novas dependências de runtime.

Feedback HTML incorporado: `EvidenceRecord.collection_performed` é opcional e estruturado; HIBP disabled/chave ausente não aparece como coleta observada, ao contrário de consultas realizadas negativas/positivas/inconclusivas. Evidências de API e cache preservam o estado de coleta original. Registros HIBP antigos sem metadado são tratados conservadoramente. Enums conhecidos traduzidos em pt-BR sem alterar respostas/literais; percent/entities sem conteúdo sensível preservados, e e-mails/controles ocultos sanitizados sem prosa como regra de classificação.

Manifesto da etapa 3 (criados ou alterados):

- `src/mailrecon/cli/app.py`, `src/mailrecon/cli/offline.py`.
- `src/mailrecon/core/models.py`, `src/mailrecon/core/catalog_cli.py`, `src/mailrecon/core/catalog_reporting.py`.
- `src/mailrecon/reporting/html.py`.
- `src/mailrecon/services/investigation_service.py`, `src/mailrecon/services/profile_check_service.py`, `src/mailrecon/services/search_links_service.py`, `src/mailrecon/services/demo_service.py`.
- `src/mailrecon/benchmark.py`.
- `tests/test_html_reports.py`, `tests/test_offline_artifacts.py`, `tests/test_synthetic_benchmark.py`.
- `scripts/run_offline_tests.py`, `scripts/package_smoke.py`, `.github/workflows/tests.yml`.
- `README.md`, `READMEeng.md`, `docs/RELATORIO-NOTURNO-2026-10-07.md`.

QA local, sem servidor:

- `reports/demo-investigation.html`, `reports/demo-recon.html`, `reports/demo-smtp.html` (pt-BR).
- `reports/demo-en/demo-investigation.html`, `reports/demo-en/demo-recon.html`, `reports/demo-en/demo-smtp.html` (en).
- JSON e Markdown sintéticos adjacentes; `reports/` permanece ignorado pelo Git.

Os arquivos são reproduzíveis por `mailrecon demo --output-dir reports` e `mailrecon --language en demo --output-dir reports/demo-en`. Se já existirem, escolha outro diretório; não há sobrescrita automática. Os timestamps da demo são fixos, não observações reais.

## Extra autorizado: empacotamento e smoke offline

Bloco adicional executado na raiz compartilhada, branch `codex/mailrecon-precision`, após onboarding somente leitura. Os três commits existentes foram preservados; este extra não foi commitado nem enviado por push. Nenhum outro agente foi aberto. Não altera runtime, modelos, protocolos, versão, dependências de runtime, workflow de CI ou licença.

A lacuna foi confirmada por listagem do sdist anterior: faltavam `READMEeng.md` e `scripts/`, embora o pacote incluísse o teste dos exemplos dos dois READMEs. O novo `MANIFEST.in` mantém os defaults do setuptools e inclui explicitamente `READMEeng.md`, `.env.example`, `scripts/*.py` e `docs/*.md`. Exclui ambiente real, credenciais por nomes conhecidos, relatórios de execução, estado, ambientes virtuais e metadados locais de ferramentas/versionamento. A documentação técnica deste relatório é autorizada; não é relatório de investigação real.

`scripts/package_smoke.py` exige exatamente um wheel e um sdist do MailRecon. Valida arquivos obrigatórios, caminhos portáveis, raiz do sdist, duplicações inclusive case-insensitive, nomes sensíveis e tipos de membros. Rejeita traversal, caminhos absolutos/Windows ambíguos, links e tipos especiais; o sdist é apenas inspecionado, nunca extraído pelo smoke. Esses checks de nomes não são um detector de segredos presentes no conteúdo de arquivos com nomes permitidos.

O wheel é instalado em diretório temporário com `--no-index --no-deps --no-compile`, sem download, configuração de pip ou checagem de versão remota. O smoke executa o wrapper real instalado (`mailrecon.exe` no Windows, `mailrecon` no Linux), não `CliRunner`. Cada execução carrega um guard temporário via `sitecustomize`, bloqueando conexões/envios por socket, resolução DNS e SMTP/SMTP_SSL antes dos imports do MailRecon; `.env` permanece desabilitado. Falha de startup encerra o processo com código 91. Confirma origem dos imports e metadados no wheel instalado, entrypoint, saída de `sources` e os nove nomes esperados da demo sintética, sem consulta live. O ambiente Python existente fornece as dependências; isso não demonstra instalação autossuficiente em um ambiente vazio nem constitui sandbox de sistema operacional.

Testes novos em `tests/test_packaging.py` usam manifestos e archives sintéticos em diretórios temporários, sem depender de `dist/` preexistente. Cobrem inclusões/exclusões, itens ausentes, duplicatas, caminhos maliciosos, arquivos sensíveis, symlinks/hardlinks/FIFO/device, distribuição única, descoberta do wrapper, ambiente offline, orquestração e falha fechada. Um subprocesso com pacote fictício comprova rejeição das operações de rede antes da aplicação e a origem incorreta dos imports.

Ajuste autorizado após revisão parcial: `setuptools>=68` foi declarado somente no extra `dev` de `pyproject.toml`, com o mesmo mínimo do build-system. O teste do manifesto usa `setuptools._distutils.filelist.FileList` para verificar a semântica real do backend, sem implementar um parser paralelo. Dependências de build instaladas em ambiente isolado não garantem esse import no ambiente do pytest; a declaração explícita evita depender de setuptools preinstalado em venvs, inclusive Python 3.13, no fluxo `pip install -e '.[dev]'` seguido de pytest. Não houve download ou alteração das dependências de runtime; a compatibilidade em Python 3.13 continua sem execução local.

Resultados locais deste extra, Windows / Python 3.11.9:

- `.venv/Scripts/python.exe scripts/run_offline_tests.py -q`: **877 passed**, incluindo 94 testes novos; guard completo de rede ativo e Dotenv desabilitado.
- `.venv/Scripts/python.exe -m build --no-isolation`: **exit 0**, sdist e wheel `0.1.0` gerados; wheel construído a partir do sdist. Avisos de exclusões sem correspondência são esperados, não falhas.
- `.venv/Scripts/python.exe scripts/package_smoke.py`: **exit 0**, validação wheel/sdist e wrapper instalado com `sources`/`demo`, origem dos imports e guard aprovados.
- `git diff --check`: **exit 0**, sem erros de whitespace; avisos locais LF/CRLF não equivalem a erro.

Ambos os READMEs já continham os comandos de build sem isolamento e package smoke, portanto foram preservados. Nenhuma leitura de `.env` real, credenciais, estado ou relatórios de investigação reais; nenhuma rede real, DNS/SMTP/HIBP, teste em contas ou reutilização de código/assets do Mr.Holmes neste extra. Resultados acima são locais: Linux, Python 3.13, CI remota e revisão independente Blue não foram executados por este executor; não se presume aprovação, push ou publicação.

## Segundo extra: robustez da decodificação HTML

Bloco pequeno autorizado após revisão Blue, sem nova auditoria da raiz. Segundo atualização fornecida pelo coordenador, a revisão Blue foi somente leitura, **44/44 checks**, sem achados reportáveis. O candidato de custo quadrático na decodificação de contexto fornecido pelo operador local foi suprimido como vulnerabilidade; esta mudança é de robustez, não correção de vulnerabilidade confirmada. A cobertura canônica permanece parcial e há resíduo marcado `deferredpending` (detalhes e fechamento a esclarecer pelo coordenador). Esses resultados não constituem cobertura exaustiva, aprovação final do gate, CI remota ou publicação. Este executor não executou essa revisão nem abriu outros agentes.

`html._decoded` agora limita cada entrada/intermediário a **65.536 caracteres** e a **oito rodadas**, incluindo confirmação de estabilidade. Sem marcadores `%`/`&`, a prosa usa o caminho direto, sem truncamento global. Havendo marcadores, entradas excessivas ou sem estabilidade no orçamento retornam ausência, nunca um resultado parcial. No HTML mascarado, o valor renderizado inteiro é omitido, incluindo eventual prosa agregada na mesma célula; não se faz truncamento nem fallback para o texto raw potencialmente sensível. Literais percent/entity usuais estáveis continuam raw quando não escondem e-mail/controle. Decodificação simples e aninhada dentro do orçamento continua mascarando e-mails e neutralizando controles.

`_safe_url` rejeita orçamento esgotado tanto em masked quanto em reveal, além do limite anterior de 8.192 caracteres. Reveal preserva o campo textual raw, escapado e com controles neutralizados, sem decodificação; isso não torna a URL rejeitada clicável. JSON e modelos permanecem completos e inalterados. Scores, serviços de rede, dependências, versão, licença, CI e arquitetura de startup não foram alterados neste segundo extra.

Os dois READMEs corrigem a afirmação anterior de que demo não lê configuração: o corpo do comando offline não compõe providers nem lê/grava estado de refinamento, mas o startup normal da CLI importa configuração e chama `load_dotenv`. `PYTHON_DOTENV_DISABLED=1`, definido antes de iniciar o processo, impede a leitura de `.env`; os checks deste bloco usam esse guard. O core/startup não foi modificado.

Verificação local em Windows / Python 3.11.9:

- `.venv/Scripts/python.exe scripts/run_offline_tests.py -q tests/test_html_reports.py`: **76 passed in 1.03s**.
- `.venv/Scripts/python.exe scripts/run_offline_tests.py -q`: **913 passed in 6.02s**.
- **36 testes novos**: contagem de chamadas e soma dos caracteres processados, sem timing frágil; nesting de 64 e 4.096 camadas, fronteiras de tamanho/rodadas, e-mails/controles codificados, URLs masked/reveal, UTF-8, prosa longa comum, literais raw, modelo/JSON imutáveis, CSP e escapamento.
- `.venv/Scripts/python.exe -m build --no-isolation`: **exit 0**, wheel/sdist `0.1.0`.
- `.venv/Scripts/python.exe scripts/package_smoke.py`: **exit 0**, archives e wrapper real instalado offline aprovados.
- `git diff --check`: **exit 0**, sem erros de whitespace; avisos LF/CRLF são locais.

Arquivos deste bloco: `src/mailrecon/reporting/html.py`, `tests/test_html_reports.py`, `README.md`, `READMEeng.md` e este relatório. Sem commit/push pelo executor, rede real, leitura de `.env` real/credenciais/estado/relatórios reais ou testes em contas. Este limite é por valor e por chamada de decodificação, não um orçamento global de tamanho/tempo do relatório nem uma revisão de todos os regex de mascaramento. Linux, Python 3.13, CI remota e fechamento da cobertura Blue residual permanecem não verificados por este executor.

## Terceiro extra: contrato de dependências da CLI

A consolidação final do relatório foi pausada após o primeiro resultado remoto. Houve atraso além do prazo previsto durante a espera de autorização/acesso ao GitHub para obter logs; não se presume cumprimento do prazo nem sucesso remoto com base nos checks locais anteriores. Conforme logs públicos obtidos pelo coordenador, a [primeira CI, run 37573754882](https://github.com/Vinicius0812/mailrecon/actions/runs/37573754882), terminou em **failure nos quatro jobs**, na etapa `Offline test suite`; checkout e instalação passaram. O log Linux/Python 3.11 apresentou cinco erros de collection com `ModuleNotFoundError: No module named 'click'`, importado diretamente por `cli/app.py` e `cli/localization.py`. O resolvedor limpo instalou Typer 0.27.3, Rich 15, python-dotenv 1.2.4 e pytest 8.4.2; o ambiente local aprovado usava Typer 0.25.1 e Click 8.3.3.

[Typer 0.26.0 incorporou Click e removeu o suporte à integração com tipos/plugins Click externos](https://typer.tiangolo.com/release-notes/#0260). A CLI atual depende do contexto, exceções, classes e hooks do Click externo para localização; declarar somente Click com Typer 0.27.3 não basta para garantir o contrato. A correção conservadora em `pyproject.toml` declara **Typer `>=0.25.1,<0.26` e Click `>=8.3.3,<8.4` como dependências diretas de runtime**, partindo das versões localmente testadas. Não houve rewrite da CLI nem instalação avulsa de Click no workflow para esconder a falha.

Dois testes em `tests/test_packaging.py` verificam as faixas explícitas no TOML e nos metadados gerados pelo backend, incluindo presença de Click em runtime, mínimos conhecidos e exclusão de Typer 0.26+. Usam `tomllib`, parser de email da biblioteca padrão e setuptools já declarado em dev; nenhuma dependência adicional de testes foi introduzida. Ambos os READMEs documentam o motivo da faixa pré-0.26. SMTP, HTTP, privacidade, protocolos da CLI, licença e versão não foram alterados.

A validação deste extra inclui suíte sob guard sem rede/Dotenv, build sem isolamento, smoke do console real instalado e instalação limpa de wheel com extra dev em venv temporário. Somente o download normal das dependências do PyPI foi autorizado nesta instalação, não consultas OSINT, leitura de `.env` real/credenciais ou código arbitrário. A rede do sandbox inicialmente bloqueou pip; a instalação foi repetida com permissão de rede para tooling. **Uma segunda execução remota da CI ainda não possui resultado confirmado**; sua conclusão não será presumida a partir da reprodução local.

Resultados deste terceiro extra, Windows / Python 3.11.9:

- Testes de empacotamento sob guard: **96 passed in 0.95s**, incluindo duas regressões novas do contrato CLI.
- Suíte completa no ambiente local sob guard: **915 passed in 6.64s**.
- Build `python -m build --no-isolation`: **exit 0**, sdist e wheel `0.1.0` gerados; package smoke no ambiente local: **exit 0**.
- Instalação do wheel `[dev]` em venv temporário sem system-site-packages, pelo resolvedor normal do PyPI, somente wheels e sem cache: **exit 0**. Metadados instalados confirmam `typer<0.26,>=0.25.1` e `click<8.4,>=8.3.3`; versões resolvidas: Typer 0.25.1, Click 8.3.3, Rich 15.0.0, python-dotenv 1.2.4, pytest 8.4.2 e setuptools 84.0.0.
- `pip check` no venv limpo: **exit 0**, `No broken requirements found`.
- Suíte completa do repositório no venv limpo com dependências recém-resolvidas, guard de rede e Dotenv desabilitado: **915 passed in 6.42s**.
- Package smoke no venv limpo: **exit 0**; wheel/sdist validados, wrapper real instalado em outro diretório temporário, origem dos imports/metadados no wheel e `sources`/`demo` sob guard confirmados. Venvs temporários removidos ao final.
- `git diff --check`: **exit 0**, sem erros de whitespace; avisos LF/CRLF não são falhas.

Arquivos deste bloco: `pyproject.toml`, `tests/test_packaging.py`, ambos os READMEs e este relatório. Sem commit/push ou alteração do workflow pelo executor. Reprodução limpa local aprovada não equivale a teste em Linux/Python 3.13 ou a resultado green da CI; a consolidação final dos estados históricos do relatório continua adiada até o coordenador confirmar os próximos resultados.

## Fontes oficiais verificadas

- [GitHub REST Users](https://docs.github.com/en/rest/users/users#get-a-user).
- [GitLab Users API](https://docs.gitlab.com/api/users/).
- [actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), SHA `3d3c42e5aac5ba805825da76410c181273ba90b1`.
- [actions/setup-python v7.0.0](https://github.com/actions/setup-python/releases/tag/v7.0.0), SHA `5fda3b95a4ea91299a34e894583c3862153e4b97`.

## Limitações e compatibilidade

- Testes simulados não são integração real autorizada. Não foi executada validação contra contas reais ou servidores SMTP externos.
- Linux real, Python 3.13 e GitHub Actions remotas ainda não executados por este executor. Daybreak não executado; nenhum sucesso é presumido.
- Build/package smoke local em Windows aprovado pelo coordenador após instalação de tooling somente em `.venv`; isso não confirma build/smoke em Linux ou CI remota.
- Deadline síncrono é verificado a cada chunk recebido; não interrompe uma leitura já bloqueada no sistema operacional, que depende do timeout por operação.
- Cache é limitado, sanitizado e somente em memória; não persistente. A CLI normalmente instancia serviço novo por comando.
- Nomes allowlisted SMTP deixaram de ser compatíveis; use os IPs literais permitidos. Portas e sondagens continuam restritas. APIs oficiais são opcionais; sete fontes permanecem manuais.
- Mascaramento não é anonimização. JSON contém endereços completos; domínio, handle e contexto também podem identificar alguém. HTML não faz rede automática, mas um clique manual em hyperlink faz navegação externa.
- Datas/tipos nos links manuais são operadores interpretados pelo buscador, não prova de período, formato ou existência de resultado. O subcomando não altera contratos de refinamento antigos.
- Não foi encontrada licença declarada no repositório: observação, não um gate antes do push. Nenhuma licença foi escolhida, criada ou alterada; uma futura decisão de licenciamento cabe ao responsável e está fora deste escopo.

## Escopo adiado

RDAP, grafo de relações, histórico persistente e gestão de casos não foram implementados neste bloco. Não foram adicionados scraping de buscadores, resolução de identidade, login, recuperação de conta ou coleta privada. Ampliações futuras exigem escopo e revisão próprios.

## Pendências finais

- QA de navegador desktop/mobile, filtros/reset, estado sintético, labels e ausência de recursos remotos/overflow: **repetição pós-ajuste concluída e aprovada pelo coordenador nas 12 combinações**.
- Build/sdist/wheel e smoke de pacote em Windows: **aprovados pelo coordenador**.
- Implementação funcional da fase 3: **aceita pelo coordenador**.
- Revisão Blue parcial informada pelo coordenador: **read-only, 44/44 checks, sem achados reportáveis; cobertura canônica parcial e resíduo `deferredpending`**. Fechamento final permanece gate de publicação.
- Primeira CI remota: **failure em 4/4 jobs, etapa Offline test suite, por falta de Click no contrato de dependências**. Correção no terceiro extra; resultado da segunda CI e smoke remoto ainda não confirmados.
- Resultado Daybreak, se solicitado: **não executado**.
- Feedback Blue: **candidato de custo local do decoder suprimido como vulnerabilidade e tratado no segundo extra de robustez**; detalhes e fechamento do resíduo a esclarecer pelo coordenador.
- Commit/push/publicação: **responsabilidade do coordenador, ainda pendentes para a etapa 3**.
