# 🛡️ Nessus Conector para GLPI

[English](README.md) / [Português do Brasil](readme_pt-br.md)

![Nessus Conector](images/nessus-logo.png)

O **Nessus Conector** é um plugin para **GLPI 11** que importa dados de vulnerabilidades dos produtos **Tenable**, vincula cada achado ao ativo correspondente no GLPI, mantém um histórico completo de sincronização e transforma vulnerabilidades em chamados acionáveis — abrindo-os automaticamente quando a falha aparece e **resolvendo-os quando ela some**.

Suporta duas fontes Tenable de fábrica:

| Fonte | O que importa | Família de API |
| --- | --- | --- |
| 🖥️ **Nessus / Tenable VM** | scans, hosts e plugins de vulnerabilidade | `/scans` |
| 🌐 **Tenable WAS** | execuções de scan de aplicação web e seus achados | `/was/v2` |

---

## ✨ Funcionalidades

### 🔌 Conectividade & configuração
- 🔐 Configure a **URL da API**, **access key** e **secret key** da Tenable dentro do GLPI.
- 🔒 **Secrets criptografadas em repouso** com a chave de segurança do próprio GLPI (`GLPIKey`) — chega de API key em texto puro no banco.
- 🧪 **Teste de conexão com um clique** por provedor (Nessus VM e WAS), com latência ao vivo e mensagens de erro amigáveis.
- ⏱️ Timeout HTTP configurável, compartilhado pelos dois provedores.

### 📥 Importação
- 🔎 **Navegue** os scans do Nessus / Tenable VM direto do GLPI.
- 🌐 **Navegue** as configurações do Tenable WAS e suas execuções direto do GLPI.
- 🎚️ **Filtro de severidade por scan** — importe só as severidades que interessam (Crítica → Info).
- 🧩 **Correspondência de ativos** dos alvos importados com os itemtypes do GLPI (Computador, Equipamento de rede, Impressora, Telefone, Não gerenciado).
- 🕰️ Rastreamento de **primeira/última detecção** e flag `is_current` por achado.

### 📊 Visibilidade
- 📊 **Dashboards de severidade** por scan e consolidado entre scans, com cards clicáveis e barra de distribuição.
- 🔬 **Tela de detalhe da vulnerabilidade** com sinopse, descrição, solução, CVSS/VPR, output do plugin, portas afetadas e **chips de CVE que linkam pro NVD**.
- 🧱 **Aba no ativo** — cada ativo GLPI correspondido mostra suas vulnerabilidades atuais inline.
- 🗂️ **Histórico de sincronização** com status, duração e contagem de hosts/vulnerabilidades.
- 📋 **Log de atividade** registrando syncs, falhas e resoluções automáticas de chamados.

### 🎫 Chamados
- 🎫 **Chamados individuais** a partir de uma vulnerabilidade, com corpo HTML estilizado (hero por severidade, contexto do alvo, links de CVE, tabela de risco, portas afetadas, solução).
- 🌳 **Chamados agrupados em hierarquia pai → filho**: um chamado **pai** por host afetado mais um chamado **filho** por vulnerabilidade, ligados pela relação nativa `SON_OF` do GLPI — o painel *Chamados vinculados* mostra a árvore inteira.
- 🖥️ **Chamados de host pendente** quando um alvo é importado mas ainda não foi vinculado a um ativo GLPI.
- ♻️ **Deduplicação inteligente** — chamados/pais existentes são reaproveitados em vez de duplicados.

### 🤖 Automação
- ⚙️ **Worker de sincronização em segundo plano (cron)** — a sincronização não depende mais de manter uma aba aberta:
  - `queue` (a cada 5 min): drena os jobs de sincronização pendentes de forma desatendida.
  - `autosync` (diário): reenfileira scans ativos que estão na hora de atualizar.
- ✅ **Resolução automática de chamados** — quando uma vulnerabilidade deixa de ser detectada no ativo, o chamado vinculado é **resolvido automaticamente** (reversível) com uma nota explicativa. Um chamado pai só é resolvido quando *todos* os seus achados sumirem.

### 🎨 Experiência
- 💎 Interface premium e moderna em todas as telas (cards, chips, toasts, modais) com suporte a **dark mode**.
- 🔄 **Fila de sync ao vivo** com barra de progresso, indicador "sincronizando…" por linha e notificações em toast.
- 👤 Gestão de **permissões por perfil**.
- 🧪 **Suíte de testes automatizados** para os geradores de conteúdo dos chamados.

---

## 🆕 O que este fork acrescenta

Sobre o plugin original (dual VM + WAS), este fork foca em prontidão para produção:

- 🔐 **Secrets de API criptografadas** (`GLPIKey`), com fallback transparente para valores legados em texto puro.
- ⏱️ **Worker de cron persistente** para sincronização desatendida (`queue` + `autosync`).
- ✅ **Resolução automática** de chamados cuja vulnerabilidade não é mais detectada.
- 📋 **Log de atividade/auditoria** com visualizador read-only no menu do plugin.
- 🧪 **Suíte de testes** (compatível com PHPUnit + runner sem dependências).

---

## 🖼️ Capturas de tela

![Tela 1 do Nessus Conector](images/print1.png)

![Tela 2 do Nessus Conector](images/print2.png)

![Configuração do Nessus Conector](images/print3.png)

---

## ✅ Requisitos

- GLPI **11.0.x** (compatibilidade declarada: `>= 11.0.0` e `< 11.1.0`)
- Extensão **cURL** do PHP habilitada
- Chave de segurança do GLPI presente (padrão em qualquer instalação — necessária para criptografar as secrets)
- Credenciais de API da Tenable (access key + secret key)
- Um perfil de usuário com as permissões do **Nessus Conector** habilitadas

Testado com **PHP 8.5**.

---

## 🚀 Instalação

Coloque o diretório do plugin dentro do GLPI:

```text
plugins/nessusglpi
```

Depois instale e ative pela interface do GLPI, ou via CLI:

```bash
php bin/console glpi:plugin:install --force --username=glpi --no-interaction nessusglpi
php bin/console glpi:plugin:activate --no-interaction nessusglpi
php bin/console cache:clear
```

> ⬆️ **Atualizando de uma versão anterior?** Vá em **Configurar → Plugins** e clique em **Atualizar** no *Nessus Conector* para que as novas tarefas de cron sejam registradas.

Após instalar, abra seu perfil no GLPI e habilite as permissões do **Nessus Conector**.

---

## 🔑 Configuração

Vá em **Plugins → Nessus Conector → Configuração** e preencha:

| Campo | Exemplo |
| --- | --- |
| URL da API (Tenable Cloud) | `https://cloud.tenable.com` |
| URL da API (Nessus local) | `https://nessus.example.local:8834` |
| Access key | sua access key da Tenable |
| Secret key | sua secret key da Tenable 🔐 *(guardada criptografada)* |
| Timeout | `30` |
| Tipos de ativo para correspondência | Computador, Equipamento de rede, Impressora, Telefone, Não gerenciado |

Use o botão de teste correspondente — **Testar conexão Nessus/VM** ou **Testar conexão WAS** — para validar as credenciais antes de salvar.

---

## 🖥️ Fluxo Nessus / Tenable VM

1. Vá em **Plugins → Nessus Conector → Scans**.
2. Clique em **Navegar scans Nessus / Tenable VM**.
3. Escolha um scan e clique em **Usar este scan** (o formulário é preenchido com o ID numérico).
4. Selecione as severidades a importar e **salve**.
5. A sincronização é enfileirada e processada pelo worker em segundo plano. 🎉

> Para scans VM, use o `id` numérico retornado por `/scans`.

## 🌐 Fluxo Tenable WAS

1. Vá em **Plugins → Nessus Conector → Scans**.
2. Clique em **Navegar scans Tenable WAS**.
3. Selecione uma **configuração** WAS e depois uma **execução de scan**.
4. Clique em **Usar este scan** (o formulário é preenchido com o UUID da execução).
5. Selecione as severidades a importar e **salve**.

> Para WAS, use o **UUID da execução**, não o ID da configuração.

---

## 🔄 Sincronização & worker em segundo plano

A sincronização é **baseada em fila**: criar ou sincronizar um scan enfileira um job, e o job importa hosts e vulnerabilidades para as tabelas do plugin.

Duas ações automáticas do GLPI (cron) mantêm tudo rodando **sem precisar de aba aberta**:

| Tarefa | Frequência padrão | O que faz |
| --- | --- | --- |
| `queue` | a cada 5 minutos | Drena os jobs de sincronização pendentes (limitado por execução). |
| `autosync` | diária | Reenfileira scans ativos cujo último sync é mais antigo que a frequência da tarefa. |

Gerencie em **Configurar → Ações automáticas**. Por padrão rodam no modo cron interno do GLPI; para uso pesado ou totalmente desatendido, troque para **externo** (cron do sistema). A página de listagem de scans também continua drenando a fila ao vivo enquanto estiver aberta.

---

## ✅ Resolução automática de chamados

Após cada sincronização bem-sucedida, o plugin verifica os chamados que criou:

- Se uma vulnerabilidade **não é mais detectada** no ativo (nenhum achado atual com a mesma identidade), o chamado vinculado vai para **Solucionado** com um acompanhamento explicativo.
- A resolução é **reversível** — o solicitante pode reabrir o chamado.
- Um chamado **pai** só é resolvido quando **todos** os achados filhos sumirem.

---

## 🧩 Correspondência de ativos

Os alvos importados são correspondidos a ativos do GLPI usando:

- hostname
- FQDN
- endereço IP
- `name` do ativo no GLPI

Para o Tenable WAS, a URL da aplicação web é reduzida a hostname/domínio antes da correspondência.

---

## 👤 Permissões por perfil

| Permissão | Finalidade |
| --- | --- |
| `plugin_nessusglpi_scan` | Ver/criar/atualizar scans e rodar sincronização |
| `plugin_nessusglpi_config` | Ver/atualizar a configuração da API e o log de atividade |
| `plugin_nessusglpi_vulnerability` | Ver vulnerabilidades e hosts importados |
| `plugin_nessusglpi_ticket` | Permissões de vínculo de chamado declaradas pelo plugin |

> Se as permissões mudarem com o usuário logado, saia e entre novamente para atualizar a sessão do GLPI.

---

## 🧪 Testes

Os geradores de conteúdo dos chamados (puros, sem banco) têm uma suíte automatizada.

```bash
# Runner sem dependências (não precisa de PHPUnit)
php tests/run.php

# Ou, num ambiente de desenvolvimento com PHPUnit
vendor/bin/phpunit -c phpunit.xml.dist
```

---

## ⚠️ Aviso de retenção de dados

**Não** desinstale o plugin se quiser manter os dados importados. A desinstalação remove as tabelas do plugin (scans, hosts, vulnerabilidades, histórico de sync, vínculos de chamado, configuração e log de atividade) e suas tarefas de cron. Para desativá-lo temporariamente, use **desativação**.

---

## 🧰 Comandos CLI úteis

```bash
php bin/console glpi:plugin:list
php bin/console glpi:plugin:install --force --username=glpi --no-interaction nessusglpi
php bin/console glpi:plugin:activate --no-interaction nessusglpi
php bin/console cache:clear

# Validar um arquivo PHP
php -l plugins/nessusglpi/src/TenableWasClient.php
```

Um guia técnico detalhado está disponível em [`COMO_FUNCIONA.md`](COMO_FUNCIONA.md).

---

## 🙏 Créditos

Este plugin é construído sobre o trabalho dos autores originais — mantenha o crédito a eles:

- 🏁 **Projeto original:** [**magaiverpr**](https://github.com/magaiverpr/NessusConector) — o *NessusConector* upstream do qual este trabalho foi forkado.
- 🧱 **Autor do plugin dual (VM + WAS):** **Daniel Berton**.
- 🔧 **Este fork** acrescenta o worker de cron em segundo plano, a criptografia das secrets, a resolução automática de chamados, o log de atividade e a suíte de testes.

Repositório upstream: <https://github.com/magaiverpr/NessusConector>

---

## 🤝 Contribuindo

Contribuições são bem-vindas via forks e pull requests:

1. Faça um fork do repositório.
2. Crie um branch de feature.
3. Faça commits focados.
4. Abra um pull request com notas claras de teste.

---

## 📄 Licença

Distribuído sob a licença **AGPL-3.0**. Veja o arquivo de licença do repositório para detalhes.
