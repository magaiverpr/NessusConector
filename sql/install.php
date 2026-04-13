<?php

declare(strict_types=1);

function plugin_nessusglpi_run_install(): bool
{
    global $DB;

    $queries = [
        "CREATE TABLE IF NOT EXISTS `glpi_plugin_nessusglpi_configs` (
            `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
            `api_url` VARCHAR(255) DEFAULT NULL,
            `access_key` VARCHAR(255) DEFAULT NULL,
            `secret_key` VARCHAR(255) DEFAULT NULL,
            `timeout` INT UNSIGNED NOT NULL DEFAULT 30,
            `allowed_itemtypes` JSON DEFAULT NULL,
            `date_mod` TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (`id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        "CREATE TABLE IF NOT EXISTS `glpi_plugin_nessusglpi_scans` (
            `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
            `name` VARCHAR(255) NOT NULL,
            `scan_id` VARCHAR(64) NOT NULL,
            `entities_id` INT NOT NULL DEFAULT 0,
            `is_active` TINYINT(1) NOT NULL DEFAULT 1,
            `last_scan_at` TIMESTAMP NULL DEFAULT NULL,
            `last_sync_at` TIMESTAMP NULL DEFAULT NULL,
            `last_sync_status` VARCHAR(32) DEFAULT NULL,
            `comment` TEXT DEFAULT NULL,
            `date_creation` TIMESTAMP NULL DEFAULT NULL,
            `date_mod` TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `scan_id` (`scan_id`),
            KEY `entities_id` (`entities_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        "CREATE TABLE IF NOT EXISTS `glpi_plugin_nessusglpi_scan_runs` (
            `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
            `plugin_nessusglpi_scans_id` INT UNSIGNED NOT NULL,
            `started_at` TIMESTAMP NULL DEFAULT NULL,
            `finished_at` TIMESTAMP NULL DEFAULT NULL,
            `status` VARCHAR(32) NOT NULL DEFAULT 'running',
            `hosts_found` INT UNSIGNED NOT NULL DEFAULT 0,
            `vulnerabilities_found` INT UNSIGNED NOT NULL DEFAULT 0,
            `message` TEXT DEFAULT NULL,
            `date_creation` TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `plugin_nessusglpi_scans_id` (`plugin_nessusglpi_scans_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        "CREATE TABLE IF NOT EXISTS `glpi_plugin_nessusglpi_hosts` (
            `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
            `plugin_nessusglpi_scan_runs_id` INT UNSIGNED NOT NULL,
            `plugin_nessusglpi_scans_id` INT UNSIGNED NOT NULL,
            `nessus_host_id` VARCHAR(64) DEFAULT NULL,
            `hostname` VARCHAR(255) DEFAULT NULL,
            `fqdn` VARCHAR(255) DEFAULT NULL,
            `ip` VARCHAR(64) DEFAULT NULL,
            `itemtype` VARCHAR(100) DEFAULT NULL,
            `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
            `match_status` VARCHAR(32) NOT NULL DEFAULT 'pending',
            `match_message` TEXT DEFAULT NULL,
            `date_creation` TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `scan_run` (`plugin_nessusglpi_scan_runs_id`),
            KEY `asset_link` (`itemtype`, `items_id`),
            KEY `nessus_host_id` (`nessus_host_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        "CREATE TABLE IF NOT EXISTS `glpi_plugin_nessusglpi_vulnerabilities` (
            `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
            `plugin_nessusglpi_scan_runs_id` INT UNSIGNED NOT NULL,
            `plugin_nessusglpi_hosts_id` INT UNSIGNED NOT NULL,
            `plugin_nessusglpi_scans_id` INT UNSIGNED NOT NULL,
            `itemtype` VARCHAR(100) DEFAULT NULL,
            `items_id` INT UNSIGNED NOT NULL DEFAULT 0,
            `vuln_key` VARCHAR(255) NOT NULL,
            `plugin_id_nessus` VARCHAR(64) DEFAULT NULL,
            `plugin_name` VARCHAR(255) DEFAULT NULL,
            `severity` INT NOT NULL DEFAULT 0,
            `severity_label` VARCHAR(32) DEFAULT NULL,
            `cve` TEXT DEFAULT NULL,
            `port` VARCHAR(32) DEFAULT NULL,
            `protocol` VARCHAR(16) DEFAULT NULL,
            `synopsis` TEXT DEFAULT NULL,
            `description` LONGTEXT DEFAULT NULL,
            `solution` LONGTEXT DEFAULT NULL,
            `plugin_output` LONGTEXT DEFAULT NULL,
            `risk_factor` VARCHAR(32) DEFAULT NULL,
            `cvss_base_score` DECIMAL(4,1) DEFAULT NULL,
            `is_current` TINYINT(1) NOT NULL DEFAULT 1,
            `first_seen_at` TIMESTAMP NULL DEFAULT NULL,
            `last_seen_at` TIMESTAMP NULL DEFAULT NULL,
            `status` VARCHAR(32) NOT NULL DEFAULT 'open',
            `date_creation` TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `vuln_key` (`vuln_key`),
            KEY `asset_link` (`itemtype`, `items_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        "CREATE TABLE IF NOT EXISTS `glpi_plugin_nessusglpi_vulnerability_tickets` (
            `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
            `plugin_nessusglpi_vulnerabilities_id` INT UNSIGNED NOT NULL,
            `tickets_id` INT UNSIGNED NOT NULL,
            `date_creation` TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `plugin_nessusglpi_vulnerabilities_id` (`plugin_nessusglpi_vulnerabilities_id`),
            KEY `tickets_id` (`tickets_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        "CREATE TABLE IF NOT EXISTS `glpi_plugin_nessusglpi_host_tickets` (
            `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
            `plugin_nessusglpi_hosts_id` INT UNSIGNED NOT NULL,
            `tickets_id` INT UNSIGNED NOT NULL,
            `date_creation` TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `plugin_nessusglpi_hosts_id` (`plugin_nessusglpi_hosts_id`),
            KEY `tickets_id` (`tickets_id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
        "CREATE TABLE IF NOT EXISTS `glpi_plugin_nessusglpi_logs` (
            `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
            `level` VARCHAR(16) NOT NULL DEFAULT 'info',
            `context` VARCHAR(64) DEFAULT NULL,
            `message` TEXT NOT NULL,
            `payload` LONGTEXT DEFAULT NULL,
            `date_creation` TIMESTAMP NULL DEFAULT NULL,
            PRIMARY KEY (`id`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    ];

    foreach ($queries as $query) {
        if (!$DB->doQuery($query)) {
            return false;
        }
    }

    $upgradeQueries = [
        "ALTER TABLE `glpi_plugin_nessusglpi_scans` ADD COLUMN `entities_id` INT NOT NULL DEFAULT 0 AFTER `scan_id`",
        "ALTER TABLE `glpi_plugin_nessusglpi_scans` ADD KEY `entities_id` (`entities_id`)",
        "ALTER TABLE `glpi_plugin_nessusglpi_scans` ADD COLUMN `last_scan_at` TIMESTAMP NULL DEFAULT NULL AFTER `is_active`",
        "ALTER TABLE `glpi_plugin_nessusglpi_hosts` ADD COLUMN `nessus_host_id` VARCHAR(64) DEFAULT NULL AFTER `plugin_nessusglpi_scans_id`",
        "ALTER TABLE `glpi_plugin_nessusglpi_hosts` ADD KEY `nessus_host_id` (`nessus_host_id`)",
    ];

    foreach ($upgradeQueries as $query) {
        try {
            $DB->doQuery($query);
        } catch (Throwable $e) {
        }
    }

    $configTable = 'glpi_plugin_nessusglpi_configs';
    $exists = $DB->request([
        'FROM'  => $configTable,
        'LIMIT' => 1,
    ])->current();

    if (!$exists) {
        $DB->insert($configTable, [
            'timeout'           => 30,
            'allowed_itemtypes' => json_encode([
                'Computer',
                'NetworkEquipment',
                'Printer',
                'Phone',
                'Unmanaged',
            ], JSON_THROW_ON_ERROR),
            'date_mod'          => date('Y-m-d H:i:s'),
        ]);
    }

    return true;
}
