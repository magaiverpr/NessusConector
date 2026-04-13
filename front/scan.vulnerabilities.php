<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Host;
use GlpiPlugin\Nessusglpi\Vulnerability;

include('../../../inc/includes.php');

Session::checkRight(Vulnerability::$rightname, READ);

$scanId = (int) ($_GET['scan_id'] ?? 0);
if ($scanId <= 0) {
    Html::displayErrorAndDie(__('Scan not found.', 'nessusglpi'));
}

$scan = new GlpiPlugin\Nessusglpi\Scan();
if (!$scan->getFromDB($scanId) || !GlpiPlugin\Nessusglpi\Scan::canAccessScanId($scanId)) {
    Html::displayErrorAndDie(__('Scan not found.', 'nessusglpi'));
}

function nessusglpi_severity_meta(array $row): array
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
        'label' => $label,
        'background' => $style[0],
        'color' => $style[1],
        'key' => $style[2],
    ];
}

function nessusglpi_severity_badge(array $row): string
{
    $meta = nessusglpi_severity_meta($row);

    return '<span style="display:inline-block; min-width:88px; text-align:center; padding:4px 10px; border-radius:999px; background:' . $meta['background'] . '; color:' . $meta['color'] . '; font-weight:600;">' . Html::cleanInputText($meta['label']) . '</span>';
}

function nessusglpi_render_dashboard(array $counts): string
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

function nessusglpi_ticket_for_vulnerability(array $vulnerabilityRow): ?array
{
    global $DB;

    $equivalentIds = Vulnerability::getEquivalentVulnerabilityIds($vulnerabilityRow);
    if ($equivalentIds === []) {
        return null;
    }

    $iterator = $DB->request([
        'FROM'  => GlpiPlugin\Nessusglpi\VulnerabilityTicket::getTable(),
        'WHERE' => [
            'plugin_nessusglpi_vulnerabilities_id' => $equivalentIds,
        ],
        'ORDER' => ['id DESC'],
    ]);

    foreach ($iterator as $link) {
        $ticketId = (int) ($link['tickets_id'] ?? 0);
        if ($ticketId <= 0) {
            continue;
        }

        $ticket = new Ticket();
        if (!$ticket->getFromDB($ticketId)) {
            continue;
        }

        if ((int) ($ticket->fields['is_deleted'] ?? 0) !== 0) {
            continue;
        }

        return [
            'id'   => (int) $ticket->fields['id'],
            'name' => (string) ($ticket->fields['name'] ?? ''),
            'link' => $ticket->getLinkURL(),
        ];
    }

    return null;
}

function nessusglpi_host_label(array $hostRow): string
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

function nessusglpi_host_cell(array $row, array $hostRow): string
{
    $label = nessusglpi_host_label($hostRow);
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

Html::header(__('Scan vulnerabilities', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

echo "<div class='card card-body'>";
echo '<h2>' . __('Scan vulnerabilities', 'nessusglpi') . '</h2>';
echo '<div style="margin-bottom:16px;">';
echo '<strong>' . __('Scan', 'nessusglpi') . ':</strong> ' . Html::cleanInputText((string) ($scan->fields['name'] ?? ''));
echo ' <span style="color:#667085;">(#' . (int) $scan->fields['id'] . ' / ' . Html::cleanInputText((string) ($scan->fields['scan_id'] ?? '')) . ')</span>';
echo '</div>';
echo '<div style="margin-bottom:16px;"><a class="btn btn-outline-secondary" href="scan.php">' . __('Back') . '</a></div>';

global $DB;

$rows = [];
$severityCounts = [
    'critical' => ['label' => 'Critical', 'background' => '#8f233f', 'color' => '#ffffff', 'count' => 0],
    'high' => ['label' => 'High', 'background' => '#d94f4f', 'color' => '#ffffff', 'count' => 0],
    'medium' => ['label' => 'Medium', 'background' => '#f6a14a', 'color' => '#1f2937', 'count' => 0],
    'low' => ['label' => 'Low', 'background' => '#f2d15c', 'color' => '#1f2937', 'count' => 0],
    'info' => ['label' => 'Info', 'background' => '#6aa7df', 'color' => '#0f172a', 'count' => 0],
];

$iterator = $DB->request([
    'FROM'  => GlpiPlugin\Nessusglpi\Vulnerability::getTable(),
    'WHERE' => [
        'plugin_nessusglpi_scans_id' => $scanId,
        'is_current'                 => 1,
    ],
    'ORDER' => [
        'severity DESC',
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

    $ticket = nessusglpi_ticket_for_vulnerability($row);
    $detailsUrl = 'vulnerability.form.php?id=' . (int) $row['id'];
    $severityMeta = nessusglpi_severity_meta($row);
    if (isset($severityCounts[$severityMeta['key']])) {
        $severityCounts[$severityMeta['key']]['count']++;
    }

    $rows[] = [
        'severity' => nessusglpi_severity_badge($row),
        'name'     => Html::cleanInputText((string) ($row['plugin_name'] ?? '')),
        'host'     => nessusglpi_host_cell($row, $hostRow),
        'ticket'   => $ticket,
        'id'       => (int) $row['id'],
        'details'  => $detailsUrl,
    ];
}

if ($rows === []) {
    echo '<p style="color:#6b7280;">' . __('No vulnerabilities imported for this scan yet.', 'nessusglpi') . '</p>';
} else {
    echo nessusglpi_render_dashboard($severityCounts);
    $bulkFormId = 'nessusglpi-scan-bulk-ticket-form';
    echo '<div style="margin-top:20px; overflow-x:auto;">';
    echo '<form id="' . $bulkFormId . '" method="post" action="vulnerability.ticket.php">';
    echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
    echo '</form>';
    echo '<div style="margin-bottom: 12px; display:flex; gap:10px; align-items:center;">';
    echo '<label style="display:flex; align-items:center; gap:8px; margin:0;"><input type="checkbox" onclick="document.querySelectorAll(\'.nessusglpi-vuln-checkbox\').forEach(function(el){el.checked=this.checked;}.bind(this))">' . Html::cleanInputText(__('Select all', 'nessusglpi')) . '</label>';
    echo '<button type="submit" form="' . $bulkFormId . '" class="btn btn-primary btn-sm" name="create_selected_tickets" value="1">' . Html::cleanInputText(__('Create selected tickets', 'nessusglpi')) . '</button>';
    echo '</div>';
    echo '<table class="tab_cadre_fixehov">';
    echo '<tr><th style="width:40px;"></th><th>' . __('Severity', 'nessusglpi') . '</th><th>' . __('Name') . '</th><th>' . __('Host', 'nessusglpi') . '</th><th>' . __('Ticket') . '</th><th>' . __('Actions') . '</th></tr>';

    foreach ($rows as $row) {
        echo '<tr>';
        echo '<td>';
        if (!is_array($row['ticket'])) {
            echo '<input class="nessusglpi-vuln-checkbox" type="checkbox" name="ids[]" value="' . (int) $row['id'] . '" form="' . $bulkFormId . '">';
        } else {
            echo '&nbsp;';
        }
        echo '</td>';
        echo '<td>' . $row['severity'] . '</td>';
        echo '<td>' . $row['name'] . '</td>';
        echo '<td>' . $row['host'] . '</td>';

        if (is_array($row['ticket'])) {
            $label = '#' . (int) $row['ticket']['id'];
            if (!empty($row['ticket']['name'])) {
                $label .= ' - ' . (string) $row['ticket']['name'];
            }
            echo '<td><a href="' . Html::cleanInputText((string) $row['ticket']['link']) . '">' . Html::cleanInputText($label) . '</a></td>';
        } else {
            echo '<td>-</td>';
        }

        echo '<td style="white-space:nowrap;">';
        echo '<a class="btn btn-sm btn-outline-primary" href="' . Html::cleanInputText((string) $row['details']) . '" style="margin-right:6px;">' . __('Show details', 'nessusglpi') . '</a>';

        if (is_array($row['ticket'])) {
            echo '<a class="btn btn-sm btn-outline-secondary" href="' . Html::cleanInputText((string) $row['ticket']['link']) . '">' . __('View') . '</a>';
            echo '<form method="post" action="vulnerability.ticket.php" style="display:inline-block; margin:0 0 0 6px;">';
            echo Html::hidden('id', ['value' => (int) $row['id']]);
            echo Html::hidden('force_new', ['value' => 1]);
            echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
            echo Html::submit(__('Open new ticket', 'nessusglpi'), ['name' => 'force_new_ticket', 'class' => 'btn btn-sm btn-outline-primary']);
            echo '</form>';
        } else {
            echo '<form method="post" action="vulnerability.ticket.php" style="display:inline-block; margin:0;">';
            echo Html::hidden('id', ['value' => (int) $row['id']]);
            echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
            echo Html::submit(__('Create ticket', 'nessusglpi'), ['name' => 'create_ticket', 'class' => 'btn btn-sm btn-primary']);
            echo '</form>';
        }

        echo '</td>';
        echo '</tr>';
    }

    echo '</table>';
    echo '</div>';
}

echo '</div>';
Html::footer();
