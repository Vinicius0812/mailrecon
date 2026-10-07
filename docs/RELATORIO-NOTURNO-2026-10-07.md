# Relatório Noturno MailRecon - 2026-10-07

## Estado final

Entrega funcional consolidada na [branch codex/mailrecon-precision](https://github.com/Vinicius0812/mailrecon/tree/codex/mailrecon-precision), com **seis commits funcionais publicados**, discriminados abaixo. A atualização deste relatório é documental e separada desses commits funcionais. A branch `main` permanece intacta, sem PR ou merge. **SHA funcional validado pela CI2:** `4ac710a6584a8ecb1a95f560541a0c903724c40f`; não é uma identificação permanente do HEAD da branch após atualizações documentais.

| Commit funcional publicado | Entrega |
| --- | --- |
| [74f6373](https://github.com/Vinicius0812/mailrecon/commit/74f6373) | Hardening SMTP, parser e proteção do terminal |
| [42d4422](https://github.com/Vinicius0812/mailrecon/commit/42d4422) | APIs públicas limitadas, catálogo e privacidade de inferências |
| [6457aa7](https://github.com/Vinicius0812/mailrecon/commit/6457aa7) | HTML offline, demos sintéticas, links manuais e benchmark |
| [d7f5f64](https://github.com/Vinicius0812/mailrecon/commit/d7f5f64) | Empacotamento e smoke offline do console instalado |
| [119d9ff](https://github.com/Vinicius0812/mailrecon/commit/119d9ff) | Decodificação HTML limitada e privacidade fail-closed |
| [4ac710a](https://github.com/Vinicius0812/mailrecon/commit/4ac710a6584a8ecb1a95f560541a0c903724c40f) | Contrato conservador de dependências Typer/Click |

**CI2 concluída com success em 4/4 jobs**, Windows/Linux e Python 3.11/3.13, com todos os steps aprovados, no SHA acima: [run 37608344374](https://github.com/Vinicius0812/mailrecon/actions/runs/37608344374). A [primeira CI, run 37573754882](https://github.com/Vinicius0812/mailrecon/actions/runs/37573754882), terminou em failure e permanece registrada como marco histórico, não como estado vigente.

Os estados remotos e as passagens Blue descritos abaixo foram confirmados pelo coordenador. O executor realizou implementações e verificações locais; não fez commit/push, não abriu outros agentes e não iniciou nova auditoria durante esta consolidação.

O prazo de 06h foi ultrapassado: houve espera de autorização/acesso ao GitHub para obter logs públicos, seguida de diagnóstico, correção de dependências e nova CI. A conclusão funcional com CI2 confirmada é posterior às 06h; o ponto de situação informado foi **07h38 de São Paulo / 10h38 UTC**. Esse registro não promete um horário para todas as ações futuras de documentação ou integração.

## Plano implementado

1. **SMTP e parser:** normalização única de transporte/host/domínio; mock com whitespace/case sem rede; allowlist restritiva, sem autorização de IP público. `localhost` literal conecta a loopback; `private-lab` exige IP literal permitido, sem resolução DNS. Gates de ambiente/confirmação, portas e sondagens preservados. Controles de terminal neutralizados e e-mails mascarados nos erros pt-BR/en, sem ocultar flags.
2. **Catálogo e validação pública:** catálogo próprio tipado, com GitHub/GitLab como únicas APIs automatizadas, para username exato. Payload genérico, login/soft 404, handle/URL divergentes e corpos inválidos são inconclusivos. Handle case-insensitive com URL canônica estrita; sete fontes permanecem pivôs manuais. Confiança de perfil não confirma identidade nem titularidade de e-mail.
3. **Limites e privacidade:** orçamento por investigação/fonte, máximo de bytes, streaming bruto e deadline monotônico, sem retries, redirects ou proxies do ambiente. Bloqueio/429 desabilita a fonte na execução. Cache sanitizado em memória com TTL/capacidade e timestamp original; prioridade reconstruída do pivô atual, inclusive zero. HIBP não recebe candidatos inferidos por padrão; entradas diretas/explícitas mantêm a política existente. `rerun-last --no-hibp` só reduz consultas. Exclusões por fingerprint precedem HTTP/cache; estado não cria destinos HTTP arbitrários.
4. **HTML e proveniência:** exportação estática para Recon, Investigation e SMTP nos seis comandos de relatório; pt-BR/en, tabelas responsivas, filtros, origem, método, regra/versão e timestamps. `collection_performed` distingue coleta HIBP observada de disabled/chave ausente; registros antigos sem metadado são hipóteses. Classificação não infere coleta a partir da prosa. Dados escapados, controles neutralizados, links sem credenciais, CSP por hashes e ausência de recursos remotos/JSON bruto embutido.
5. **Artefatos e benchmark:** `sources`, `demo` e `search-links` sem consultas de rede. Nove arquivos sintéticos por idioma, sem sobrescrita; JSON/Markdown/HTML com timestamps fixos, não observações reais. Links com datas/tipos são sugestões manuais, não achados. Benchmark próprio com 21 fixtures positivas/negativas/ambíguas; precisão e falsos positivos se referem apenas a esse conjunto.
6. **CI própria:** matriz Windows/Linux e Python 3.11/3.13, testes com guard, benchmark, build wheel/sdist e smoke instalado. Permissões `contents: read`, timeout de 15 minutos, sem segredos e sem persistência de credenciais no checkout. Actions oficiais fixadas por SHA; nenhum workflow de terceiro copiado.

## Extras discriminados

### Empacotamento e smoke

O sdist anterior não continha `READMEeng.md` nem `scripts/`, embora incluísse o teste dos dois READMEs. `MANIFEST.in` mantém os defaults do setuptools e inclui explicitamente `READMEeng.md`, `.env.example`, `scripts/*.py` e `docs/*.md`; exclui ambiente real, credenciais por nomes conhecidos, relatórios de investigação, estado, venvs e metadados locais. A documentação técnica deste relatório não é relatório de investigação real.

`scripts/package_smoke.py` exige um wheel e um sdist, verifica arquivos obrigatórios, raiz, duplicações case-insensitive, caminhos portáveis e nomes/tipos sensíveis. Rejeita traversal, caminhos absolutos/ambíguos, links e tipos especiais; inspeciona o sdist sem extraí-lo. O wheel validado é instalado em diretório temporário com `--no-index --no-deps --no-compile`, sem download ou configuração de pip.

O smoke executa o **wrapper real instalado**, `mailrecon.exe` ou `mailrecon`, não apenas `CliRunner`. Guard temporário via `sitecustomize` bloqueia conexões/envios por socket, DNS e SMTP/SMTP_SSL antes dos imports do projeto; falha de startup encerra com código 91. Confirma origem dos imports/metadados no wheel, entrypoint, saída de `sources` e os nove nomes da demo.

Os testes de archives são sintéticos e independem de `dist/` preexistente. `setuptools>=68` foi declarado somente em dev porque o teste do manifesto usa o parser real `FileList`; build isolado não garante sua disponibilidade no pytest. Não houve mudança de dependências de runtime nesse primeiro extra.

### Decodificação HTML limitada

O custo quadrático do decoder foi tratado como robustez local, não como vulnerabilidade reportável confirmada. `html._decoded` limita entradas/intermediários a **65.536 caracteres e oito rodadas**, incluindo confirmação de estabilidade. Prosa sem `%`/`&` segue o caminho direto, sem truncamento global. Valores com marcadores acima do tamanho permitido ou sem estabilidade são omitidos por inteiro no HTML mascarado, inclusive prosa agregada na mesma célula: nunca fallback para raw ou parcialmente decodificado.

Literais percent/entity estáveis sem e-mail/controle oculto permanecem raw dentro do orçamento. `_safe_url` rejeita orçamento esgotado em masked e reveal, além do limite anterior de 8.192 caracteres. Reveal textual mantém raw escapado e controles neutralizados, sem decodificação, mas não torna URLs rejeitadas clicáveis. JSON/modelos permanecem completos; scores, serviços de rede, protocolos e startup não foram alterados.

Os 36 testes novos medem chamadas e caracteres processados, sem timing frágil, com 64/4.096 camadas, fronteiras, e-mails/controles codificados, URLs, UTF-8, literais, modelo/JSON imutáveis, CSP e escapamento. Os READMEs corrigem o escopo de demo: seu corpo offline não compõe providers nem lê/grava refinamento, mas o startup da CLI importa configuração e chama `load_dotenv`. `PYTHON_DOTENV_DISABLED=1`, definido antes do processo, impede leitura de `.env`; o core/startup permanece inalterado.

### Dependências da CLI

A primeira CI falhou em 4/4 jobs na etapa `Offline test suite`; checkout e instalação passaram. O log Linux/Python 3.11 apresentou cinco erros de collection, `ModuleNotFoundError: No module named 'click'`. O resolvedor selecionou Typer 0.27.3, Rich 15, python-dotenv 1.2.4 e pytest 8.4.2; o ambiente local aprovado tinha Typer 0.25.1/Click 8.3.3.

[Typer 0.26.0 incorporou Click e removeu suporte a integrações Click externas](https://typer.tiangolo.com/release-notes/#0260). Como a localização usa contextos, exceções, classes e hooks externos, a correção declara **Typer `>=0.25.1,<0.26` e Click `>=8.3.3,<8.4` diretamente em runtime**. Não houve rewrite da CLI ou instalação avulsa no workflow para esconder o problema.

As duas regressões verificam o TOML e os metadados do backend via `Distribution` **em memória**. Esse teste não valida isoladamente um wheel/sdist real. A prova separada é o build seguido de instalação limpa do wheel, leitura de seus metadados instalados, `pip check` e smoke do console real com guard. Nenhuma dependência adicional de testes foi introduzida.

## Verificação e marcos

Os números abaixo são marcos históricos; não são resultados contraditórios da mesma revisão.

| Marco | Resultado |
| --- | --- |
| Baseline | 455 testes |
| SMTP/parser/allowlist | 523 testes |
| APIs/catálogo/privacidade | 706 testes |
| HTML inicial / buscas e demo | 721 / 745 testes |
| Feedback HTML / ajuste visual | 777 / 783 testes |
| Empacotamento | 877 testes, incluindo 94 novos |
| Decoder limitado | 913 testes; HTML 76 em 1,03s |
| Repetição do coordenador após decoder | 913 sob guard em 6,03s |
| Contrato CLI, ambiente local | 915 sob guard em 6,64s; packaging 96 em 0,95s |
| Wheel com dev em venv limpo | 915 sob guard em 6,42s |
| CI1 | Failure 4/4; collection sem Click |
| CI2 no SHA publicado final | Success 4/4; todos os steps |

As verificações locais finais foram em Windows/Python 3.11.9. `python scripts/run_offline_tests.py -q` bloqueia saída de rede, DNS e SMTP, com Dotenv desabilitado. `python -m build --no-isolation`, wheel/sdist, package smoke local e limpo, `pip check` e `git diff --check` passaram com **exit 0**. Avisos de exclusões sem correspondência no manifesto e de LF/CRLF não são falhas. A CI2 acrescenta execução remota aprovada em Windows/Linux, Python 3.11/3.13.

A instalação limpa usou wheel `[dev]` em venv temporário sem system-site-packages, resolvedor normal do PyPI, somente wheels e sem cache. Resolveu Typer 0.25.1, Click 8.3.3, Rich 15.0.0, python-dotenv 1.2.4, pytest 8.4.2 e setuptools 84.0.0. Metadados instalados confirmaram os limites Typer/Click e `pip check` retornou `No broken requirements found`. Apenas o download de tooling/dependências foi autorizado; testes e smoke seguiram offline. O bloqueio inicial de rede do sandbox foi superado por permissão de tooling; os ambientes temporários foram removidos.

O benchmark reproduziu **21/21 classificações**, dois verdadeiros positivos, zero falsos positivos/negativos e precisão 1,0 somente nas fixtures próprias. Revisões locais anteriores informadas pelo coordenador cobriram 126 testes críticos de SMTP e 136 de APIs/privacidade; uma revisão independente da fase 1 cobriu 73 casos. Nenhum desses resultados mede identidade ou acurácia real.

**Browser QA concluído nas 12 combinações** Recon/Investigation/SMTP × pt-BR/en × desktop 1280x900/mobile 390x844, após o ajuste visual de tabelas/título. Filtros/reset, labels, ausência de erros JS, rede remota e overflow aprovados; filtro observado das demos sintéticas retorna zero. Esse QA antecede bounded decode; CSS não mudou nesse extra. Não se declara uma nova rodada de navegador posterior ao decoder. Capturas locais não são links públicos de prova neste documento.

## Segurança e revisão Blue

Passagens reais informadas pelo coordenador, todas read-only na CLI **0.155.1**, modelo **gpt-daybreak-blue-latest**:

| Passagem | Faixa e cobertura de fonte | Reasoning | Resultado |
| --- | --- | --- | --- |
| Revisão pré-fix | `94e8dbd..d7f5f64`, 44/44 arquivos | medium | exit 0; zero reportáveis |
| Follow-up HTML | `d7f5f64..119d9ff`, 5/5 arquivos | medium | exit 0; zero reportáveis |
| Follow-up de dependências/metadados | `119d9ff..4ac710a`, 5/5 arquivos | low | exit 0; zero findings de regressão |

Essa é **cobertura de fonte das faixas indicadas**, não cobertura exaustiva do repositório. Os follow-ups são passagens estáticas separadas: não executaram a suíte do projeto nem substituem a prova de instalação/CI. A validação isolada do candidato na primeira passagem é distinta dessas suítes.

O candidato `FD01` reproduziu trabalho quadrático no decoder, com entrada de aproximadamente 16 kB, cerca de 64 milhões de caracteres processados e execução isolada de 1,078s. Foi suprimido como vulnerabilidade porque o caminho dependia de entrada do operador ou escrita local protegida, sem boundary externo sustentado. A robustez foi corrigida em `119d9ff` mesmo assim; não se apresenta FD01 como vulnerabilidade vigente.

O scan canônico selado, identificado pelo prefixo `60abfc8b`, **permanece inalterado e com cobertura parcial**. Seu checkpoint de FD01 permanece `deferredpending`, apesar da validação final suprimida como vulnerabilidade. O revisor identificou somente um mecanismo compatível com ausência de `candidateId` e merge de lista vazia; não reconstituiu qual snapshot foi incorporado ao selo. Trata-se de hipótese de consolidação não reconstituída, não de causa MCP definitivamente comprovada. A leitura dos 44 arquivos e os follow-ups não equivalem à cobertura canônica completa. Esse resíduo selado não significa uma vulnerabilidade ativa; zero reportáveis nas passagens também não comprova ausência de toda vulnerabilidade. Não foi reaberto, alterado ou declarado full o scan selado nesta entrega.

## Limitações e compatibilidade

- Todas as demos, respostas simuladas e fixtures são sintéticas. Nenhum teste do MailRecon usou credencial real de coleta ou realizou teste em contas reais, SMTP externo, login em alvos, recuperação de senha, coleta privada ou evasão. Houve autenticação GitHub autorizada para Git/CI; isso é distinto de credenciais de coleta do MailRecon. Rede autorizada para tooling/CI e documentação oficial não é coleta OSINT.
- O guard Python bloqueia as operações previstas, mas não é sandbox de sistema operacional. Checks de nomes dos archives não detectam segredos dentro de conteúdo com nome permitido; o smoke sem dependências pressupõe dependências disponíveis no seu ambiente.
- O limite do decoder é por valor/chamada, não orçamento global do relatório nem revisão de todos os regex. Um campo agregado pode ser omitido inteiro ao esgotar o orçamento. Reveal e JSON/modelos mantêm dados originais conforme o contrato.
- Deadline síncrono é verificado por chunk e não interrompe leitura já bloqueada no sistema operacional; esta depende do timeout da operação. Cache é limitado, sanitizado, somente em memória e sem persistência entre processos.
- Allowlist SMTP não aceita mais nomes de host como autorização; use IP literal permitido. Portas 25/465/587 continuam bloqueadas fora de loopback; `expn` permanece exclusivo de localhost. Mock/no-network não abre conexão.
- Typer deve permanecer na faixa pré-0.26 declarada enquanto a CLI usa Click externo. O mínimo de setuptools em dev atende o parser do manifesto; dependências isoladas de build não garantem o ambiente de testes.
- Mascaramento não é anonimização: domínio, handle e contexto podem identificar alguém; JSON e estado de refinamento contêm dados completos. Controle acesso/retenção e não publique relatórios reais, chaves ou estados. HIBP negativo, DNS, perfil público e simulação não confirmam identidade ou caixa postal.
- HTML não acessa rede automaticamente; clicar em hyperlink permitido é ação manual de rede. Datas/tipos em links de busca não comprovam período, formato, cobertura ou existência de resultado.
- Não foram usados código, listas, assets ou licença do Mr.Holmes. Não foi encontrada licença declarada no repositório; nenhuma foi escolhida, copiada, criada ou alterada. A decisão futura cabe ao responsável, sem ser apresentada como impedimento retrospectivo ao push já realizado.
- Os seis commits funcionais estão publicados e a CI2 aprovou o SHA funcional indicado; atualizações documentais são separadas. Integração em main não ocorreu. A cobertura canônica parcial é uma ressalva explícita, não uma alegação de auditoria integral.

## Escopo adiado

RDAP, grafo de relações, histórico persistente e gestão de casos ficam fora da entrega. Scraping de buscadores, resolução automatizada de identidade, login, recuperação de conta e coleta privada não foram adicionados. Migração para Typer com Click incorporado e reconciliação futura do checkpoint canônico exigem escopos próprios; este relatório não altera o artefato selado.

## Nota técnica e referências

Medição agregada do workbench em **dois chats**: 7.412.355 tokens totais, 7.380.327 de input, 7.168.384 de cached input e 32.028 de output. Cached input é parte do input, não uma parcela adicional ao total. Esses valores agregados não representam custo monetário nem consumo isolado de Blue.

- [GitHub REST Users](https://docs.github.com/en/rest/users/users#get-a-user).
- [GitLab Users API](https://docs.gitlab.com/api/users/).
- [Typer: release notes e mudança 0.26.0](https://typer.tiangolo.com/release-notes/#0260).
- [actions/checkout v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1), SHA `3d3c42e5aac5ba805825da76410c181273ba90b1`.
- [actions/setup-python v7.0.0](https://github.com/actions/setup-python/releases/tag/v7.0.0), SHA `5fda3b95a4ea91299a34e894583c3862153e4b97`.

Esta consolidação usa os resultados fornecidos pelo coordenador e os checks locais já registrados. Nesta atualização final foram editados somente este documento e conferido o diff; sem nova implementação, auditoria, CI, subagente ou commit/push pelo executor.
