<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\ScanRun;

include('../../../inc/includes.php');

Session::checkRight(ScanRun::$rightname, READ);

Html::header(__('Scan history', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

global $DB;

echo "<div class='card card-body'>";
echo "<h2>" . __('Scan history', 'nessusglpi') . "</h2>";
echo "<table class='tab_cadre_fixehov'>";
echo "<tr><th>ID</th><th>" . __('Entity') . "</th><th>" . __('Scan', 'nessusglpi') . "</th><th>" . __('Status') . "</th><th>" . __('Started at', 'nessusglpi') . "</th><th>" . __('Finished at', 'nessusglpi') . "</th></tr>";

$iterator = $DB->request([
    'SELECT' => [
        'glpi_plugin_nessusglpi_scan_runs.*',
        'glpi_plugin_nessusglpi_scans.entities_id AS scan_entity_id',
        'glpi_plugin_nessusglpi_scans.name AS scan_name',
        'glpi_plugin_nessusglpi_scans.scan_id AS nessus_scan_id',
    ],
    'FROM'   => 'glpi_plugin_nessusglpi_scan_runs',
    'LEFT JOIN' => [
        'glpi_plugin_nessusglpi_scans' => [
            'FKEY' => [
                'glpi_plugin_nessusglpi_scan_runs' => 'plugin_nessusglpi_scans_id',
                'glpi_plugin_nessusglpi_scans'    => 'id',
            ],
        ],
    ],
    'WHERE' => Scan::getVisibleScansCriteria(),
    'ORDER' => ['glpi_plugin_nessusglpi_scan_runs.id DESC'],
]);

foreach ($iterator as $row) {
    echo "<tr>";
    echo "<td>" . (int) $row['id'] . "</td>";
    echo "<td>" . Html::cleanInputText(Dropdown::getDropdownName('glpi_entities', (int) ($row['scan_entity_id'] ?? 0))) . "</td>";
    echo "<td>" . Html::cleanInputText((string) ($row['scan_name'] ?? '-')) . ' <span style=\"color:#667085;\">(' . Html::cleanInputText((string) ($row['nessus_scan_id'] ?? '')) . ')</span>' . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['status'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['started_at'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['finished_at'] ?? ''), ENT_QUOTES) . "</td>";
    echo "</tr>";
}

echo "</table>";
echo "</div>";
Html::footer();
