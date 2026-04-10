# Nessus Conector

 en-US / [pt-BR](readme_pt-br.md)

This plugin aims to connect Nessus with GLPI to synchronize vulnerabilities found with assets, generating a history and creating tickets based on each vulnerability found for internal handling and documentation.

## Configuration
To configure the plugin, you only need the Nessus API URL, the access key, and the secret key generated for the API. After saving the configuration, retrieve the ID of a scan performed in Nessus (found in the Nessus URL, as shown in the screenshot below).

<img src="/images/print3.png">

When synchronizing the scan, it will automatically search for hosts based on their name or IP address registered in the GLPI asset list. If it doesn't find any, it will also show the hostname, but the one found by Nessus.

## Images
<img src="/images/print1.png">
<img src="/images/print2.png">