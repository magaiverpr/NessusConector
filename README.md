# Nessus GLPI Plugin Skeleton

Esqueleto inicial de um plugin GLPI 11.0.4 para integrar resultados do Nessus.

## Nome interno do plugin

O identificador interno usado no código é `nessusglpi`.

Ao instalar no GLPI, o diretório do plugin deve ter esse nome:

`plugins/nessusglpi`

## Entregue nesta etapa

- estrutura base do plugin
- hooks de instalação e desinstalação
- tabelas iniciais do banco
- classes principais do domínio
- telas mínimas para configuração, scans, hosts e vulnerabilidades
- serviços stub para sincronização e criação de tickets

## Próximos passos

1. Implementar o cliente HTTP real da API do Nessus.
2. Implementar matching de assets e persistência do resultado da sincronização.
3. Adicionar busca/listagem com colunas customizadas.
4. Implementar criação real de tickets.

## Traducoes

A base de internacionalizacao do plugin fica em `locales/`.

Idiomas iniciais preparados:
- `en_GB`
- `fr_FR`
- `pt_BR`

Para regenerar os catalogos apos alterar textos do plugin:

```bash
python tools/update_locales.py
```

O script atualiza:
- `locales/nessusglpi.pot`
- `locales/en_GB.po`
- `locales/fr_FR.po`
- `locales/pt_BR.po`

Observacao: os catalogos foram iniciados como base de trabalho. Uma revisao linguistica posterior ainda e recomendada antes da publicacao.
