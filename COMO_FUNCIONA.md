# Como funciona o plugin Nessus Conector

Este documento explica o plugin `nessusglpi` passo a passo: instalacao, permissoes, configuracao, sincronizacao com o Nessus, gravacao no banco, telas do GLPI e criacao de tickets.

O plugin integra scans do Nessus / Tenable VM e do Tenable WAS ao GLPI. Ele busca hosts e vulnerabilidades pela API, tenta vincular cada host a um ativo do GLPI, grava historico de sincronizacoes, sincroniza de forma desatendida por cron, e cria e resolve tickets automaticamente a partir das vulnerabilidades encontradas.

## 1. Estrutura do plugin

Arquivos principais:

| Caminho | Funcao |
| --- | --- |
| `setup.php` | Registra o plugin no GLPI, menu, pagina de configuracao, abas e compatibilidade. |
| `hook.php` | Executa instalacao/desinstalacao e chama os scripts SQL. |
| `sql/install.php` | Cria tabelas do plugin e registro padrao de configuracao. |
| `sql/uninstall.php` | Remove as tabelas do plugin. |
| `src/Profile.php` | Define os direitos/permissoes do plugin por perfil. |
| `src/Config.php` | Guarda URL/chaves da API Nessus (secret key criptografada com GLPIKey), timeout e tipos de ativos permitidos. |
| `src/NessusClient.php` | Cliente HTTP/cURL usado para conversar com a API do Nessus. |
| `src/TenableWasClient.php` | Cliente HTTP/cURL usado para conversar com a API Tenable WAS. |
| `src/Scan.php` | Representa os scans cadastrados no GLPI e monta o menu principal. |
| `src/SyncJobService.php` | Controla a fila de sincronizacao. |
| `src/SyncService.php` | Faz a sincronizacao de fato: Nessus -> GLPI. |
| `src/AssetMatcher.php` | Tenta casar host do Nessus com ativo existente no GLPI. |
| `src/Vulnerability.php` | Mostra vulnerabilidades em scans e nas abas dos ativos. |
| `src/TicketService.php` | Cria tickets no GLPI a partir de vulnerabilidades ou hosts pendentes, e resolve tickets cuja vulnerabilidade nao e mais detectada. |
| `src/SyncCron.php` | Tarefas de cron: processa a fila e reenfileira scans ativos sem precisar de aba aberta. |
| `src/AuditLog.php` | Grava o log de atividade do plugin (sincronizacoes, falhas, resolucoes automaticas). |
| `front/*.php` | Telas HTML acessadas pelo usuario no GLPI. |
| `ajax/*.php` | Endpoints AJAX para fila e criacao de tickets. |
| `locales/*` | Traducoes do plugin. |
| `tests/` | Suite de testes dos geradores de conteudo de ticket (PHPUnit + runner sem dependencias). |

Namespace PHP principal:

```text
GlpiPlugin\Nessusglpi
```

Compatibilidade declarada:

```text
GLPI 11.0.0 ate 11.0.99
Plugin 1.3.0
```

## 2. O que o plugin cria no banco

Na instalacao, o plugin cria tabelas proprias:

| Tabela | O que guarda |
| --- | --- |
| `glpi_plugin_nessusglpi_configs` | Configuracao da API Nessus: URL, access key, secret key (criptografada em repouso com GLPIKey), timeout e tipos de ativos permitidos. |
| `glpi_plugin_nessusglpi_scans` | Scans cadastrados no GLPI, com o ID/UUID externo e tipo da origem: `nessus` ou `was`. |
| `glpi_plugin_nessusglpi_scan_runs` | Historico de execucoes/sincronizacoes. |
| `glpi_plugin_nessusglpi_sync_jobs` | Fila de sincronizacao. |
| `glpi_plugin_nessusglpi_hosts` | Hosts importados do Nessus. |
| `glpi_plugin_nessusglpi_vulnerabilities` | Vulnerabilidades importadas. Mantem historico e marca quais estao atuais. |
| `glpi_plugin_nessusglpi_vulnerability_tickets` | Relacao entre vulnerabilidade e ticket criado. |
| `glpi_plugin_nessusglpi_host_tickets` | Relacao entre host pendente e ticket criado. |
| `glpi_plugin_nessusglpi_logs` | Log de atividade do plugin: sincronizacoes, falhas e resolucoes automaticas de ticket. |

Tambem cria direitos em `glpi_profilerights` para controlar acesso por perfil.

## 3. Permissoes do GLPI

O plugin usa direitos proprios. Eles aparecem na aba `Nessus Conector` dentro do cadastro de perfil do GLPI.

| Direito | Permissoes possiveis | Uso principal |
| --- | --- | --- |
| `plugin_nessusglpi_scan` | READ, UPDATE, CREATE | Ver menu/scans, cadastrar scan, editar scan, sincronizar, apagar scans, ver historico. |
| `plugin_nessusglpi_config` | READ, UPDATE | Ver e alterar configuracao da API Nessus. |
| `plugin_nessusglpi_vulnerability` | READ, UPDATE | Ver vulnerabilidades, hosts importados e criar tickets pela tela de vulnerabilidades/hosts. |
| `plugin_nessusglpi_ticket` | READ, CREATE | Direito declarado para vinculos de ticket. No codigo atual, as rotas de criacao validam principalmente `plugin_nessusglpi_vulnerability` com UPDATE. |

Ponto importante: se os direitos forem alterados no banco ou por reinstalacao do plugin, a sessao ativa do usuario pode continuar com os direitos antigos. Quando aparecer erro como:

```text
User is missing the 1 (READ) right for plugin_nessusglpi_config
User is missing the 1 (READ) right for plugin_nessusglpi_scan
```

faca logout/login no GLPI ou limpe a sessao. O perfil pode estar correto no banco, mas a sessao ainda estar carregada sem os direitos novos.

No codigo atual deste ambiente, a instalacao tambem garante direitos padrao para o perfil `Super-Admin`.

## 4. Fluxo de instalacao

1. O diretorio do plugin precisa existir em:

   ```text
   plugins/nessusglpi
   ```

2. O GLPI carrega `setup.php`.

3. O metodo `plugin_init_nessusglpi()` registra:

   - menu em `Plugins -> Nessus Conector`;
   - pagina de configuracao;
   - aba de permissoes no perfil;
   - aba de vulnerabilidades em ativos GLPI.

4. Na instalacao, `hook.php` chama:

   ```text
   sql/install.php
   Profile::ensureProfileRights()
   ```

5. `sql/install.php` cria as tabelas e uma configuracao padrao.

6. `Profile::ensureProfileRights()` cria os direitos do plugin em todos os perfis.

7. Depois disso, o plugin precisa estar ativado no GLPI.

Via CLI, o fluxo equivalente e:

```bash
docker compose exec glpi-fpm php bin/console glpi:plugin:install --force --username=glpi --no-interaction nessusglpi
docker compose exec glpi-fpm php bin/console glpi:plugin:activate --no-interaction nessusglpi
docker compose exec glpi-fpm php bin/console cache:clear
```

## 5. Configuracao inicial no GLPI

Passo a passo:

1. Entrar no GLPI com usuario administrador.

2. Ir em:

   ```text
   Plugins -> Nessus Conector -> Configuration
   ```

3. Preencher:

   | Campo | Exemplo | Observacao |
   | --- | --- | --- |
   | API URL | `https://nessus.exemplo.local:8834` | Deve ser URL http/https valida. |
   | API URL para Tenable Cloud/WAS | `https://cloud.tenable.com` | Use este formato quando a origem for Tenable Cloud ou WAS. |
   | Access key | chave do Nessus | Gerada no Nessus. |
   | Secret key | segredo do Nessus | Gerada no Nessus. |
   | Timeout | `30` | Timeout em segundos. |
   | Allowed itemtypes | `Computer`, `NetworkEquipment`, etc. | Tipos de ativos que podem ser vinculados. |

4. Clicar em `Test Nessus/VM connection` para Nessus/Tenable VM ou `Test WAS connection` para Tenable WAS.

5. Se o teste funcionar, salvar a configuracao.

O teste de conexao Nessus/VM usa:

```text
GET /server/status
```

O teste de conexao WAS usa:

```text
POST /was/v2/configs/search?limit=1
```

Cabecalho usado na API:

```text
X-ApiKeys: accessKey=...; secretKey=...
Accept: application/json
```

Observacao de seguranca: o cliente atual desativa validacao SSL no cURL (`CURLOPT_SSL_VERIFYPEER=false` e `CURLOPT_SSL_VERIFYHOST=0`). Isso ajuda em ambientes internos com certificado proprio, mas em producao o ideal e validar certificado corretamente.

## 6. Cadastro de scans

Para cadastrar um scan Nessus/Tenable VM:

1. No Nessus, abrir o relatorio/scan desejado.

   Tambem e possivel clicar em `Browse Nessus / Tenable VM scans` no plugin para listar os scans pela API e preencher o formulario automaticamente.

2. Pegar o ID do scan. Normalmente ele aparece na URL, por exemplo:

   ```text
   https://nessus.local:8834/#/scans/reports/123/scan-summary
   ```

   Nesse exemplo, o ID e:

   ```text
   123
   ```

3. No GLPI, ir em:

   ```text
   Plugins -> Nessus Conector -> Scans -> Add
   ```

4. Selecionar a origem `Nessus / Tenable VM`.

5. Informar o `Scan ID`. Para Nessus/Tenable VM, prefira o `id` numerico retornado pela listagem `/scans`.

6. Selecionar as severidades que devem ser importadas:

   | Valor Nessus | Label |
   | --- | --- |
   | 4 | Critical |
   | 3 | High |
   | 2 | Medium |
   | 1 | Low |
   | 0 | Info |

7. Ao salvar, o plugin consulta:

   ```text
   GET /scans/{scan_id}
   ```

8. O nome do scan vem de `info.name` ou `name`.

9. O plugin grava o scan em `glpi_plugin_nessusglpi_scans` com `scan_type = nessus`.

10. Uma sincronizacao inicial e colocada na fila em `glpi_plugin_nessusglpi_sync_jobs`.

### 6.1 Cadastro de scans Tenable WAS

Tenable WAS e outra API. O ID usado pelo plugin e o UUID de uma execucao WAS.

No plugin, o caminho mais simples e:

1. Ir em `Plugins -> Nessus Conector -> Scans`.

2. Clicar em `Browse Tenable WAS scans`.

3. Escolher a configuracao WAS.

4. Escolher a execucao.

5. Clicar em `Use this scan`.

6. O formulario de scan abre com `Source = Tenable WAS` e `Scan ID` preenchido.

Para descobrir os IDs via API:

1. Listar configuracoes WAS:

   ```bash
   curl -s -X POST 'https://cloud.tenable.com/was/v2/configs/search?limit=200' \
     -H 'X-ApiKeys: accessKey=SUA_ACCESS_KEY; secretKey=SUA_SECRET_KEY' \
     -H 'accept: application/json' \
     -H 'content-type: application/json' \
     -d '{}'
   ```

2. Pegar o `config_id` da aplicacao desejada.

3. Listar as execucoes/scans daquela configuracao:

   ```bash
   curl -s -X POST 'https://cloud.tenable.com/was/v2/configs/CONFIG_ID/scans/search?limit=200' \
     -H 'X-ApiKeys: accessKey=SUA_ACCESS_KEY; secretKey=SUA_SECRET_KEY' \
     -H 'accept: application/json' \
     -H 'content-type: application/json' \
     -d '{}'
   ```

4. Pegar o UUID do scan retornado.

5. No GLPI, ir em:

   ```text
   Plugins -> Nessus Conector -> Scans -> Add
   ```

6. Selecionar a origem `Tenable WAS`.

7. Informar o UUID do scan WAS no campo `Scan ID`.

8. Ao salvar, o plugin consulta:

   ```text
   GET /was/v2/scans/{scan_uuid}
   ```

9. A sincronizacao importa findings usando:

   ```text
   POST /was/v2/scans/{scan_uuid}/vulnerabilities/search
   ```

10. O plugin grava o scan em `glpi_plugin_nessusglpi_scans` com `scan_type = was`.

## 7. Como a fila de sincronizacao funciona

O plugin tem uma fila que e processada de duas formas: ao vivo pela tela de scans e, de forma desatendida, por tarefas de cron do GLPI.

### 7.1 Processamento ao vivo (tela aberta)

O funcionamento e:

1. Um scan e criado ou o usuario clica em `Sync`.

2. `SyncJobService::queueScan()` cria um job com status:

   ```text
   pending
   ```

3. A tela de scans (`front/scan.php`) detecta jobs pendentes ou em execucao.

4. Essa tela injeta um JavaScript que chama:

   ```text
   ajax/sync.queue.php
   ```

5. O endpoint AJAX chama:

   ```php
   SyncJobService::processNextPendingJob()
   ```

6. O job muda para:

   ```text
   running
   ```

7. `SyncService::runScan()` faz a sincronizacao real.

8. No final, o job vira:

   ```text
   success
   ```

   ou:

   ```text
   error
   ```

### 7.2 Processamento por cron (sem aba aberta)

A partir da versao 1.3.0 o plugin registra duas tarefas de cron (itemtype `GlpiPlugin\Nessusglpi\SyncCron`), gerenciaveis em `Configurar -> Acoes automaticas`:

| Tarefa | Frequencia padrao | O que faz |
| --- | --- | --- |
| `queue` | a cada 5 min | Drena os jobs pendentes da fila (limitado a 10 por execucao). |
| `autosync` | diaria | Reenfileira scans ativos cujo ultimo sync e mais antigo que a frequencia da tarefa. |

Por padrao rodam no modo cron interno do GLPI (disparado nos acessos as paginas). Para uso pesado ou totalmente desatendido, troque o modo da tarefa para externo e configure o cron do sistema. A tela de scans continua drenando a fila ao vivo quando esta aberta.

> Apos atualizar o plugin de uma versao anterior, abra `Configurar -> Plugins` e clique em `Atualizar` para que as tarefas de cron sejam registradas.

## 8. Fluxo completo da sincronizacao

Resumo:

```text
Scan cadastrado no GLPI
  -> cria job pendente
  -> tela de scans chama AJAX
  -> SyncJobService processa o job
  -> SyncService consulta o Nessus
  -> importa hosts
  -> tenta casar hosts com ativos GLPI
  -> importa vulnerabilidades filtradas por severidade
  -> marca vulnerabilidades atuais e antigas
  -> grava historico da execucao
```

Passo a passo interno de `SyncService::runScan()`:

1. Carrega o scan da tabela `glpi_plugin_nessusglpi_scans`.

2. Cria uma linha em `glpi_plugin_nessusglpi_scan_runs` com status `running`.

3. Atualiza o scan com status de sincronizacao `running`.

4. Busca detalhes do scan no Nessus:

   ```text
   GET /scans/{scan_id}
   ```

5. Le a lista de hosts em `hosts`.

6. Para cada host, busca detalhes:

   ```text
   GET /scans/{scan_id}/hosts/{host_id}
   ```

7. Normaliza dados do host:

   - `nessus_host_id`;
   - `hostname`;
   - `fqdn`;
   - `ip`.

8. Remove duplicados dentro da mesma execucao.

9. Tenta vincular o host a um ativo GLPI usando `AssetMatcher`.

10. Grava ou atualiza o host importado em `glpi_plugin_nessusglpi_hosts`.

11. Marca vulnerabilidades atuais anteriores como antigas (`is_current = 0`) para aquele host/ativo.

12. Extrai vulnerabilidades do retorno do Nessus.

13. Filtra pelas severidades configuradas no scan.

14. Gera uma chave unica da vulnerabilidade (`vuln_key`) usando dados como ativo/host, plugin Nessus, porta e protocolo.

15. Insere as vulnerabilidades em `glpi_plugin_nessusglpi_vulnerabilities` com:

   ```text
   is_current = 1
   status = open
   first_seen_at
   last_seen_at
   ```

16. Ao finalizar, atualiza o run e o scan com status `success`.

17. Aciona a resolucao automatica de tickets: chamados cuja vulnerabilidade nao aparece mais sao marcados como solucionados (ver secao 13).

18. Se ocorrer erro, salva status `error` e a mensagem do erro.

### 8.1 Sincronizacao Tenable WAS

Quando o scan esta com `scan_type = was`, o fluxo muda:

1. O plugin busca detalhes do scan WAS:

   ```text
   GET /was/v2/scans/{scan_uuid}
   ```

2. Depois busca findings/vulnerabilidades:

   ```text
   POST /was/v2/scans/{scan_uuid}/vulnerabilities/search
   ```

3. Cada finding WAS e normalizado para o modelo atual do plugin:

   - a aplicacao/URL vira um host importado;
   - o dominio da URL vira `fqdn`/`hostname`;
   - o UUID/ID do finding vira `plugin_id_nessus`;
   - nome, severidade, descricao, solucao, prova/evidencia, request/response e URL entram na vulnerabilidade;
   - o matching com ativo GLPI continua tentando achar ativo pelo `name`.

4. O detalhe de vulnerabilidade WAS usa os dados ja salvos na sincronizacao. Ele nao chama os endpoints antigos de host/plugin do Nessus.

## 9. Como o plugin identifica ativos do GLPI

O arquivo responsavel e:

```text
src/AssetMatcher.php
```

Tipos de ativos suportados por configuracao:

```text
Computer
NetworkEquipment
Printer
Phone
Unmanaged
```

Regra atual de casamento:

1. Monta candidatos a partir de:

   - `hostname`;
   - `fqdn`.

2. Para cada tipo permitido, consulta a tabela do item no GLPI.

3. Procura ativo com:

   ```sql
   name = hostname_ou_fqdn
   ```

4. Se encontrar, grava:

   - `itemtype`;
   - `items_id`;
   - `match_status = matched`;
   - `match_message = Matched with item #...`.

5. Se nao encontrar, grava:

   - `match_status = pending`;
   - sem ativo vinculado.

Ponto de atencao: apesar do README mencionar nome/IP, o codigo atual do `AssetMatcher` faz casamento pelo campo `name`. O IP e salvo no host importado, mas nao e usado para buscar em campos de IP do GLPI.

## 10. Como as vulnerabilidades sao armazenadas

Cada vulnerabilidade importada grava dados principais do Nessus:

- plugin ID;
- plugin name;
- severidade numerica;
- label da severidade;
- CVE;
- porta;
- protocolo;
- synopsis;
- description;
- solution;
- plugin output;
- risk factor;
- CVSS;
- datas de primeira e ultima aparicao;
- status;
- relacao com scan;
- relacao com host importado;
- relacao com ativo GLPI, quando encontrado.

O plugin mantem historico. Em uma nova sincronizacao, vulnerabilidades antigas daquele host/ativo sao marcadas como:

```text
is_current = 0
```

As vulnerabilidades encontradas na sincronizacao atual ficam:

```text
is_current = 1
```

Isso permite ver somente o estado atual nas telas principais, mas ainda manter historico no banco.

## 11. Telas do plugin

Menu principal:

```text
Plugins -> Nessus Conector
```

Principais telas:

| Tela | Arquivo | Funcao |
| --- | --- | --- |
| Scans | `front/scan.php` | Lista scans, permite adicionar, editar, sincronizar, apagar e abrir vulnerabilidades. |
| Busca de scans Tenable | `front/scan.browser.php` | Lista scans Nessus/Tenable VM e configuracoes/execucoes Tenable WAS para preencher o cadastro automaticamente. |
| Formulario de scan | `front/scan.form.php` | Cadastra/edita scan e busca nome no Nessus. |
| Configuracao | `front/config.form.php` | Configura API Nessus e testa conexao. |
| Vulnerabilidades do scan | `front/scan.vulnerabilities.php` | Mostra vulnerabilidades atuais de um scan. |
| Vulnerabilidades consolidadas | `front/scans.vulnerabilities.php` | Mostra vulnerabilidades atuais de todos os scans visiveis. |
| Detalhe da vulnerabilidade | `front/vulnerability.form.php` | Busca detalhes completos do plugin Nessus e exibe descricao, solucao, CVE, outputs e metadados. |
| Lista simples de vulnerabilidades | `front/vulnerability.php` | Lista vulnerabilidades importadas. |
| Hosts importados | `front/host.php` | Mostra hosts importados e status de casamento com ativos. |
| Historico de sincronizacao | `front/scanrun.php` | Mostra runs de sincronizacao. |
| Direitos no perfil | `front/profile.rights.php` | Salva direitos do plugin no perfil. |

Abas adicionadas:

| Onde aparece | O que mostra |
| --- | --- |
| Perfil do GLPI | Aba `Nessus Conector` para configurar direitos do plugin. |
| Ativos GLPI permitidos | Aba de vulnerabilidades importadas daquele ativo. |

## 12. Detalhe de vulnerabilidade

Ao abrir o detalhe de uma vulnerabilidade, o plugin tenta buscar informacoes mais ricas no Nessus:

```text
GET /scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}
```

A tela mostra, quando disponivel:

- descricao;
- solucao;
- links `See Also`;
- output do plugin;
- portas;
- CVEs;
- host;
- scan ID;
- plugin ID;
- risk factor;
- CVSS v2;
- CVSS v3;
- VPR;
- data de publicacao;
- data de modificacao;
- data de patch;
- disponibilidade de exploit;
- CPE.

Se o Nessus nao retornar o detalhe, a tela mostra a mensagem de erro, mas ainda usa dados ja salvos na tabela de vulnerabilidades quando possivel.

## 13. Criacao de tickets

Arquivo principal:

```text
src/TicketService.php
```

O plugin consegue criar:

1. Ticket individual por vulnerabilidade.

2. Tickets agrupados por vulnerabilidade semelhante.

3. Ticket de host pendente quando o host importado nao foi vinculado a um ativo GLPI.

### Ticket individual

Fluxo:

1. Usuario seleciona uma vulnerabilidade.

2. `front/vulnerability.ticket.php` ou `ajax/vulnerability.ticket.php` chama:

   ```php
   TicketService::createTicketFromVulnerability()
   ```

3. O plugin verifica se ja existe ticket para uma vulnerabilidade equivalente.

4. Se existir e o usuario nao pediu novo ticket, reaproveita o ticket existente.

5. Se nao existir, cria um ticket GLPI com:

   - titulo com severidade, host e nome da vulnerabilidade;
   - conteudo com dados do Nessus;
   - status `1`;
   - type `1`;
   - entidade resolvida pelo scan, ativo ou entidade ativa da sessao.

6. Se houver ativo vinculado, cria relacao em `glpi_items_tickets`.

7. Grava relacao em `glpi_plugin_nessusglpi_vulnerability_tickets`.

### Ticket agrupado (pai + filhos)

Quando o usuario seleciona varias vulnerabilidades e clica em **Group & create**, o plugin agrupa pela chave:

- plugin ID Nessus;
- nome do plugin;
- porta;
- protocolo;
- severidade numerica;
- label de severidade.

Para cada grupo com 2 ou mais hosts afetados, o plugin cria uma **hierarquia pai-filho**:

- **1 chamado pai** com o overview do grupo: hero da severidade, lista de hosts afetados, sinopse/descricao/solucao, CVSS, CVEs, plugin output, footer. O pai e vinculado a todos os ativos via `glpi_items_tickets`.

- **N chamados filhos** (um por host unico do grupo). Cada filho contem o detalhe individual da vulnerabilidade naquele host, igual ao ticket individual. O filho e vinculado ao seu ativo e ao pai.

- Os filhos sao linkados ao pai via `glpi_tickets_tickets` com `link = 3` (`CommonITILObject_CommonITILObject::SON_OF`). O GLPI mostra essa arvore no painel **Chamados vinculados** do ticket.

Se o grupo tem apenas 1 host afetado, o plugin **nao** cria hierarquia: gera um unico chamado individual (igual ao botao "Create selected").

Dedup: se ja existe um chamado pai para esse grupo (detectado percorrendo `Ticket_Ticket SON_OF`), o pai e reusado e apenas filhos faltantes sao criados.

Retorno do `createGroupedTicketsFromVulnerabilities`:

```php
[
  'groups'   => [
    ['parent' => 123, 'children' => [124, 125, 126]],
    ...
  ],
  'parents'  => [123, ...],
  'children' => [124, 125, 126, ...],
]
```

### Ticket de host pendente

Quando o host do Nessus nao foi casado com ativo do GLPI, o plugin pode criar um ticket com:

- hostname;
- FQDN;
- IP;
- status de casamento;
- mensagem de detalhe.

### Resolucao automatica de tickets

Ao final de cada sincronizacao bem-sucedida, o plugin verifica os tickets que ele mesmo criou:

- se a vulnerabilidade vinculada nao e mais detectada no ativo (nenhum achado atual com a mesma identidade `vuln_key` + ativo), o ticket e movido para **Solucionado** com um acompanhamento explicativo;
- a resolucao usa `ITILSolution` e e reversivel: o solicitante pode reabrir o chamado;
- um ticket **pai** so e resolvido quando **todos** os achados filhos sumirem;
- tickets ja solucionados/fechados ou excluidos sao ignorados;
- a acao e registrada no log de atividade e nunca quebra a sincronizacao (falhas sao engolidas).

## 14. Passo a passo operacional recomendado

1. Instalar e ativar o plugin.

2. Ir no perfil do usuario administrador e confirmar direitos do `Nessus Conector`.

3. Fazer logout/login no GLPI para recarregar a sessao.

4. Configurar API URL, access key e secret key.

5. Testar conexao no modo correto: `Nessus/VM` ou `WAS`.

6. Cadastrar um scan pelo ID do Nessus/Tenable VM ou pelo UUID do scan WAS. Tambem e possivel usar os botoes `Browse Nessus / Tenable VM scans` e `Browse Tenable WAS scans`.

7. Selecionar a origem correta no cadastro do scan.

8. Voltar para a lista de scans e aguardar a fila processar.

9. Conferir status do scan:

   ```text
   success
   ```

10. Abrir `View vulnerabilities`.

11. Conferir hosts casados e pendentes.

12. Abrir detalhes das vulnerabilidades mais importantes.

13. Criar tickets individuais ou agrupados.

14. Revisar tickets no GLPI.

15. Em sincronizacoes futuras, clicar em `Sync` no scan desejado.

## 15. Logs e diagnostico

O plugin tem um **log de atividade** proprio em `Plugins -> Nessus Conector -> Activity log`, que registra sincronizacoes, falhas e resolucoes automaticas de ticket (requer direito READ em `plugin_nessusglpi_config`).

Logs uteis no ambiente Docker:

```bash
docker compose logs --tail=200 glpi-fpm
docker compose logs --tail=200 nginx
docker compose logs --tail=200 database
```

Logs internos do GLPI dentro do container:

```bash
docker compose exec glpi-fpm tail -n 120 /var/glpi/files/_log/php-errors.log
docker compose exec glpi-fpm tail -n 120 /var/glpi/files/_log/access-errors.log
docker compose exec glpi-fpm tail -n 120 /var/glpi/files/_log/sql-errors.log
```

Comandos uteis de plugin:

```bash
docker compose exec glpi-fpm php bin/console glpi:plugin:list
docker compose exec glpi-fpm php bin/console glpi:plugin:install --force --username=glpi --no-interaction nessusglpi
docker compose exec glpi-fpm php bin/console glpi:plugin:activate --no-interaction nessusglpi
docker compose exec glpi-fpm php bin/console cache:clear
```

Consultar direitos no banco:

```bash
docker compose exec database mariadb -uglpi_user -pglpi_password glpi_db -e "SELECT profiles_id, name, rights FROM glpi_profilerights WHERE name LIKE 'plugin_nessusglpi%' ORDER BY profiles_id, name;"
```

Validar sintaxe PHP de um arquivo do plugin:

```bash
docker compose exec glpi-fpm php -l /var/www/glpi/plugins/nessusglpi/src/NessusClient.php
```

## 16. Erros comuns

### Sem permissao para abrir configuracao ou scans

Mensagem comum:

```text
Voce nao tem permissao para executar essa acao.
User is missing the 1 (READ) right for plugin_nessusglpi_config
```

Possiveis causas:

- perfil sem direito do plugin;
- plugin instalado antes de criar os direitos;
- sessao do GLPI carregada antes da correcao dos direitos;
- usuario em outro perfil/entidade.

Como corrigir:

1. Verificar direitos em `Administration -> Profiles`.

2. Marcar direitos da aba `Nessus Conector`.

3. Salvar.

4. Fazer logout/login.

5. Limpar cache se necessario.

### `Function curl_close() is deprecated since 8.5`

Esse aviso aparece no PHP 8.5 porque `curl_close()` nao tem efeito desde PHP 8.0.

No codigo atual deste ambiente, as chamadas desnecessarias foram removidas de:

```text
src/NessusClient.php
```

### Fila nao processa

Sintoma:

```text
last_sync_status = queued
```

Explicacao:

A fila e processada pela tarefa de cron `queue` (a cada 5 min) e tambem ao vivo pela tela de scans.

Como testar:

1. Conferir em `Configurar -> Acoes automaticas` se a tarefa `queue` (itemtype `GlpiPlugin\Nessusglpi\SyncCron`) esta ativa e, se quiser, force a execucao por la.

2. Como alternativa, abrir `Plugins -> Nessus Conector -> Scans` e manter a tela aberta alguns segundos.

3. Atualizar e conferir status.

Se nada processar: confirme que o plugin foi atualizado para 1.3.0 (para registrar o cron) e, para uso pesado, mude o modo da tarefa para externo (cron do sistema).

### WAS nao sincroniza usando ID de configuracao

No Tenable WAS existem pelo menos dois IDs importantes:

- `config_id`: identifica a configuracao da aplicacao WAS;
- `scan_id`/UUID: identifica uma execucao daquela configuracao.

O plugin usa o UUID da execucao no campo `Scan ID`, nao o `config_id`. Use `/was/v2/configs/{config_id}/scans/search` para descobrir o UUID da execucao.

### Host nao vincula ao ativo

O casamento atual procura ativo pelo campo `name`, usando hostname ou FQDN. Se o nome do ativo no GLPI nao bater com o nome vindo do Nessus, o host fica pendente.

Solucoes:

- ajustar nome do ativo no GLPI;
- ajustar DNS/hostname no Nessus;
- melhorar o `AssetMatcher` para buscar tambem por IP.

### Scan abre no Nessus somente depois de sucesso

O botao `Open in Nessus` aparece quando:

- existe API URL configurada;
- o scan esta com `last_sync_status = success`.

## 17. Pontos de atencao tecnicos

- As chaves da API Nessus sao salvas na tabela de configuracao do plugin; a secret key e criptografada em repouso com GLPIKey (valores legados em texto puro seguem funcionando ate o proximo salvamento da configuracao).
- A validacao SSL esta desativada no cliente Nessus VM; o cliente Tenable WAS valida SSL.
- A fila de sincronizacao roda por cron (`SyncCron`) e tambem ao vivo pela tela de scans.
- O casamento de ativos usa `name`; IP ainda nao e usado para matching.
- No modo WAS, a aplicacao/URL e convertida para host importado usando o dominio da URL.
- No modo WAS, informe o UUID da execucao do scan, nao o `config_id`.
- O plugin mantem historico de vulnerabilidades, entao a tabela pode crescer com o tempo.
- A criacao de tickets tenta reaproveitar tickets existentes, salvo quando o usuario forca ticket novo.
- Os direitos `plugin_nessusglpi_ticket` existem, mas o fluxo atual de criacao de ticket usa principalmente UPDATE em vulnerabilidades/hosts.
- Os geradores de conteudo de ticket tem testes automatizados em `tests/` (rode com `php tests/run.php`, ou via PHPUnit com `phpunit.xml.dist`).

## 18. Checklist rapido

Para colocar em funcionamento:

```text
[ ] Plugin em plugins/nessusglpi
[ ] Plugin instalado
[ ] Plugin ativado
[ ] Direitos aplicados no perfil
[ ] Logout/login feito
[ ] API URL configurada
[ ] Access key configurada
[ ] Secret key configurada
[ ] Test connection correto OK
[ ] Origem correta selecionada no scan
[ ] Scan ID/UUID cadastrado
[ ] Fila processando (cron 'queue' ativo apos atualizar p/ 1.3.0, ou tela de scans aberta)
[ ] Status success
[ ] Vulnerabilidades visiveis
[ ] Hosts conferidos
[ ] Tickets criados quando necessario
```
