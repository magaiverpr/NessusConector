
# Nessus Conector

[en-US](README.md) / pt-BR

Esse plugin tem por objetivo conectar o Nessus com o GLPI, para sincronizar as vulnerabilidades achadas com os ativos para gerar um histórico e também criar chamados baseados em cada vulnerabilidade achada para tratamento e documentação interna.

## Configuração
Para configurar o plugin, basta apenas da URL da API do Nessus, a access key e o secret key gerado para a API. Após salvar a configuração, pegue o ID de um scan feito no Nessus (encontrado na URL do Nessus, conforme print abaixo).
<img src="/images/print3.png">

Ao sincronizar o scan, ele irá buscar automaticamente os hosts baseado no seu nome ou IP cadastrado na lista de ativos do GLPI. Caso não encontre, ele também irá mostrar o nome do host, mas o encontrado pelo Nessus.



## Imagens
<img src="/images/print1.png">
<img src="/images/print2.png">