<?php

declare(strict_types=1);

function plugin_nessusglpi_run_uninstall(): void
{
    global $DB;

    $tables = [
        'glpi_plugin_nessusglpi_logs',
        'glpi_plugin_nessusglpi_host_tickets',
        'glpi_plugin_nessusglpi_vulnerability_tickets',
        'glpi_plugin_nessusglpi_vulnerabilities',
        'glpi_plugin_nessusglpi_hosts',
        'glpi_plugin_nessusglpi_scan_runs',
        'glpi_plugin_nessusglpi_scans',
        'glpi_plugin_nessusglpi_configs',
    ];

    foreach ($tables as $table) {
        $DB->doQuery(sprintf('DROP TABLE IF EXISTS `%s`', $table));
    }
}
