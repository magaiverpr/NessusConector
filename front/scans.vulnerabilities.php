<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Host;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\Vulnerability;

include('../../../inc/includes.php');

Session::checkRight(Vulnerability::$rightname, READ);

function nessusglpi_consolidated_severity_meta(array $row): array
{
    $severity = (int) ($row['severity'] ?? 0);
    $label = trim((string) ($row['severity_label'] ?? ''));
    if ($label === '' || ctype_digit($label)) {
        $label = match ($severity) {
            4 => 'Critical',
            3 => 'High',
            2 => 'Medium',
            1 => 'Low',
            default => 'Info',
        };
    }

    $style = match (strtolower($label)) {
        'critical' => ['#8f233f', '#ffffff', 'critical'],
        'high' => ['#d94f4f', '#ffffff', 'high'],
        'medium' => ['#f6a14a', '#1f2937', 'medium'],
        'low' => ['#f2d15c', '#1f2937', 'low'],
        default => ['#6aa7df', '#0f172a', 'info'],
    };

    return [
        'label'      => $label,
        'background' => $style[0],
        'color'      => $style[1],
        'key'        => $style[2],
    ];
}

function nessusglpi_consolidated_severity_badge(array $row): string
{
    $meta = nessusglpi_consolidated_severity_meta($row);

    return '<span style="display:inline-block; min-width:88px; text-align:center; padding:4px 10px; border-radius:999px; background:' . $meta['background'] . '; color:' . $meta['color'] . '; font-weight:600;">' . Html::cleanInputText($meta['label']) . '</span>';
}

function nessusglpi_consolidated_render_dashboard(array $counts): string
{
    $total = array_sum(array_column($counts, 'count'));
    $html = '<div style="display:grid; grid-template-columns: repeat(5, minmax(120px, 1fr)); gap: 0; border-radius: 10px; overflow: hidden; border: 1px solid #d7dee8;">';

    foreach ($counts as $severity) {
        $html .= '<div style="background:' . $severity['background'] . '; color:' . $severity['color'] . '; min-height: 118px; display:flex; flex-direction:column; justify-content:center; align-items:center; text-align:center; padding: 12px 8px;">';
        $html .= '<div style="font-size: 30px; line-height: 1; font-weight: 700; margin-bottom: 8px;">' . (int) $severity['count'] . '</div>';
        $html .= '<div style="font-size: 16px; font-weight: 600;">' . Html::cleanInputText($severity['label']) . '</div>';
        $html .= '</div>';
    }

    $html .= '</div>';
    $html .= '<div style="margin-top: 14px; font-size: 13px; color: #667085;">' . sprintf(__('Total current vulnerabilities: %d', 'nessusglpi'), $total) . '</div>';
    $html .= '<div style="margin-top: 18px; border: 1px solid #d7dee8; border-radius: 8px; overflow: hidden; background: #f7f9fc;">';
    $html .= '<div style="display:flex; width:100%; min-height: 28px;">';

    foreach ($counts as $severity) {
        $count = (int) $severity['count'];
        $width = $total > 0 ? max(($count / $total) * 100, $count > 0 ? 4 : 0) : 20;
        $text = $count > 0 ? (string) $count : '';
        $html .= '<div title="' . htmlspecialchars($severity['label'] . ': ' . $count, ENT_QUOTES) . '" style="width:' . rtrim(rtrim(number_format($width, 2, '.', ''), '0'), '.') . '%; background:' . $severity['background'] . '; color:' . $severity['color'] . '; display:flex; align-items:center; justify-content:center; font-weight:700; font-size:12px;">' . $text . '</div>';
    }

    $html .= '</div>';
    $html .= '</div>';

    return $html;
}

function nessusglpi_consolidated_host_label(array $hostRow): string
{
    $fqdn = trim((string) ($hostRow['fqdn'] ?? ''));
    if ($fqdn !== '') {
        return $fqdn;
    }

    $hostname = trim((string) ($hostRow['hostname'] ?? ''));
    if ($hostname !== '') {
        return $hostname;
    }

    $ip = trim((string) ($hostRow['ip'] ?? ''));
    if ($ip !== '') {
        return $ip;
    }

    return __('Unknown host', 'nessusglpi');
}

function nessusglpi_consolidated_host_cell(array $row, array $hostRow): string
{
    $label = nessusglpi_consolidated_host_label($hostRow);
    $itemtype = trim((string) ($row['itemtype'] ?? $hostRow['itemtype'] ?? ''));
    $itemsId = (int) ($row['items_id'] ?? $hostRow['items_id'] ?? 0);
    if ($itemtype === '' || $itemsId <= 0) {
        return Html::cleanInputText($label);
    }

    $item = getItemForItemtype($itemtype);
    if (!$item || !$item->getFromDB($itemsId)) {
        return Html::cleanInputText($label);
    }

    return '<a href="' . Html::cleanInputText($item->getLinkURL()) . '" style="text-decoration:underline; font-weight:600;">' . Html::cleanInputText($label) . '</a>';
}

Html::header(__('Consolidated vulnerabilities', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

echo "<div class='card card-body'>";
echo '<h2>' . __('Consolidated vulnerabilities', 'nessusglpi') . '</h2>';
echo '<div style="margin-bottom:16px;">';
echo '<strong>' . __('Entities') . ':</strong> ';

$entityNames = [];
foreach (Scan::getVisibleEntityIds() as $entityId) {
    $entityName = Dropdown::getDropdownName('glpi_entities', $entityId);
    if ($entityName !== '') {
        $entityNames[] = $entityName;
    }
}

echo Html::cleanInputText(implode(', ', $entityNames) ?: __('None'));
echo '</div>';
echo '<div style="margin-bottom:16px;"><a class="btn btn-outline-secondary" href="scan.php">' . __('Back') . '</a></div>';

global $DB;

$visibleScanIds = [];
$scanMeta = [];
$scanIterator = $DB->request([
    'SELECT' => ['id', 'name', 'scan_id'],
    'FROM'   => Scan::getTable(),
    'WHERE'  => Scan::getVisibleScansCriteria(),
    'ORDER'  => ['name ASC', 'id ASC'],
]);

foreach ($scanIterator as $scanRow) {
    $scanDbId = (int) ($scanRow['id'] ?? 0);
    if ($scanDbId <= 0) {
        continue;
    }

    $visibleScanIds[] = $scanDbId;
    $scanMeta[$scanDbId] = [
        'name'    => (string) ($scanRow['name'] ?? ''),
        'scan_id' => (string) ($scanRow['scan_id'] ?? ''),
    ];
}

$rows = [];
$severityCounts = [
    'critical' => ['label' => 'Critical', 'background' => '#8f233f', 'color' => '#ffffff', 'count' => 0],
    'high'     => ['label' => 'High', 'background' => '#d94f4f', 'color' => '#ffffff', 'count' => 0],
    'medium'   => ['label' => 'Medium', 'background' => '#f6a14a', 'color' => '#1f2937', 'count' => 0],
    'low'      => ['label' => 'Low', 'background' => '#f2d15c', 'color' => '#1f2937', 'count' => 0],
    'info'     => ['label' => 'Info', 'background' => '#6aa7df', 'color' => '#0f172a', 'count' => 0],
];

if ($visibleScanIds !== []) {
    $iterator = $DB->request([
        'FROM'  => Vulnerability::getTable(),
        'WHERE' => [
            'plugin_nessusglpi_scans_id' => $visibleScanIds,
            'is_current'                 => 1,
        ],
        'ORDER' => [
            'severity DESC',
            'plugin_nessusglpi_scans_id ASC',
            'plugin_name ASC',
            'id DESC',
        ],
    ]);

    foreach ($iterator as $row) {
        $host = new Host();
        $hostRow = [];
        if ($host->getFromDB((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0))) {
            $hostRow = $host->fields;
        }

        $severityMeta = nessusglpi_consolidated_severity_meta($row);
        if (isset($severityCounts[$severityMeta['key']])) {
            $severityCounts[$severityMeta['key']]['count']++;
        }

        $scanDbId = (int) ($row['plugin_nessusglpi_scans_id'] ?? 0);
        $rows[] = [
            'severity'  => nessusglpi_consolidated_severity_badge($row),
            'name'      => Html::cleanInputText((string) ($row['plugin_name'] ?? '')),
            'host'      => nessusglpi_consolidated_host_cell($row, $hostRow),
            'scan_id'   => Html::cleanInputText((string) ($scanMeta[$scanDbId]['scan_id'] ?? '')),
            'scan_name' => Html::cleanInputText((string) ($scanMeta[$scanDbId]['name'] ?? '')),
        ];
    }
}

if ($rows === []) {
    echo '<p style="color:#6b7280;">' . __('No vulnerabilities imported for the selected entities yet.', 'nessusglpi') . '</p>';
} else {
    echo nessusglpi_consolidated_render_dashboard($severityCounts);
    echo '<div style="margin-top:20px; overflow-x:auto;">';
    echo '<table class="tab_cadre_fixehov">';
    echo '<tr><th>' . __('Severity', 'nessusglpi') . '</th><th>' . __('Name') . '</th><th>' . __('Host', 'nessusglpi') . '</th><th>' . __('Scan ID', 'nessusglpi') . '</th><th>' . __('Scan', 'nessusglpi') . '</th></tr>';

    foreach ($rows as $row) {
        echo '<tr>';
        echo '<td>' . $row['severity'] . '</td>';
        echo '<td>' . $row['name'] . '</td>';
        echo '<td>' . $row['host'] . '</td>';
        echo '<td>' . $row['scan_id'] . '</td>';
        echo '<td>' . $row['scan_name'] . '</td>';
        echo '</tr>';
    }

    echo '</table>';
    echo '</div>';
}

echo '</div>';
Html::footer();
