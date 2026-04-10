<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\ScanRun;

include('../../../inc/includes.php');

Session::checkRight(ScanRun::$rightname, READ);

Html::header(__('Scan history', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

global $DB;

echo "<div class='card card-body'>";
echo "<h2>" . __('Scan history', 'nessusglpi') . "</h2>";
echo "<table class='tab_cadre_fixehov'>";
echo "<tr><th>ID</th><th>" . __('Scan', 'nessusglpi') . "</th><th>" . __('Status') . "</th><th>" . __('Started at', 'nessusglpi') . "</th><th>" . __('Finished at', 'nessusglpi') . "</th></tr>";

foreach ($DB->request([
    'FROM'  => 'glpi_plugin_nessusglpi_scan_runs',
    'ORDER' => ['id DESC'],
]) as $row) {
    echo "<tr>";
    echo "<td>" . (int) $row['id'] . "</td>";
    echo "<td>" . (int) ($row['plugin_nessusglpi_scans_id'] ?? 0) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['status'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['started_at'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['finished_at'] ?? ''), ENT_QUOTES) . "</td>";
    echo "</tr>";
}

echo "</table>";
echo "</div>";
Html::footer();
