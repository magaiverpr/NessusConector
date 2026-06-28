<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Host;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\Vulnerability;

include('../../../inc/includes.php');

Session::checkRight(Vulnerability::$rightname, READ);

function nessusglpi_consolidated_severity_key(array $row): string
{
    $severity = (int) ($row['severity'] ?? 0);
    $label = trim((string) ($row['severity_label'] ?? ''));
    if ($label === '' || ctype_digit($label)) {
        return match ($severity) {
            4 => 'critical',
            3 => 'high',
            2 => 'medium',
            1 => 'low',
            default => 'info',
        };
    }
    $lower = strtolower($label);
    return in_array($lower, ['critical', 'high', 'medium', 'low', 'info'], true) ? $lower : 'info';
}

function nessusglpi_consolidated_severity_label(string $key): string
{
    return match ($key) {
        'critical' => __('Critical', 'nessusglpi'),
        'high' => __('High', 'nessusglpi'),
        'medium' => __('Medium', 'nessusglpi'),
        'low' => __('Low', 'nessusglpi'),
        default => __('Info', 'nessusglpi'),
    };
}

function nessusglpi_consolidated_severity_icon(string $key): string
{
    return match ($key) {
        'critical' => '💀',
        'high' => '🚨',
        'medium' => '⚠️',
        'low' => '🟡',
        default => '🔵',
    };
}

function nessusglpi_consolidated_icon(string $name): string
{
    $icons = [
        'search'  => '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
        'arrow-left' => '<path d="M19 12H5"/><path d="m12 19-7-7 7-7"/>',
        'inbox'   => '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z"/>',
    ];
    $inner = $icons[$name] ?? '<circle cx="12" cy="12" r="10"/>';
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $inner . '</svg>';
}

function nessusglpi_consolidated_host_label(array $hostRow): string
{
    $fqdn = trim((string) ($hostRow['fqdn'] ?? ''));
    if ($fqdn !== '') return $fqdn;
    $hostname = trim((string) ($hostRow['hostname'] ?? ''));
    if ($hostname !== '') return $hostname;
    $ip = trim((string) ($hostRow['ip'] ?? ''));
    if ($ip !== '') return $ip;
    return __('Unknown host', 'nessusglpi');
}

function nessusglpi_consolidated_host_link(array $row, array $hostRow): array
{
    $label = nessusglpi_consolidated_host_label($hostRow);
    $itemtype = trim((string) ($row['itemtype'] ?? $hostRow['itemtype'] ?? ''));
    $itemsId = (int) ($row['items_id'] ?? $hostRow['items_id'] ?? 0);
    if ($itemtype === '' || $itemsId <= 0) {
        return ['label' => $label, 'href' => null];
    }
    $item = getItemForItemtype($itemtype);
    if (!$item || !$item->getFromDB($itemsId)) {
        return ['label' => $label, 'href' => null];
    }
    return ['label' => $label, 'href' => $item->getLinkURL()];
}

Html::header(__('Consolidated vulnerabilities', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

global $DB, $CFG_GLPI;

$assetsBase = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
$assetVersion = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';

echo '<link rel="stylesheet" href="' . Html::cleanInputText($assetsBase . '/css/vulnerabilities.css?v=' . $assetVersion) . '">';

$entityNames = [];
foreach (Scan::getVisibleEntityIds() as $entityId) {
    $entityName = Dropdown::getDropdownName('glpi_entities', $entityId);
    if ($entityName !== '') {
        $entityNames[] = $entityName;
    }
}

$scanMeta = [];
$visibleScanIds = [];
foreach ($DB->request([
    'SELECT' => ['id', 'name', 'scan_id'],
    'FROM'   => Scan::getTable(),
    'WHERE'  => Scan::getVisibleScansCriteria(),
    'ORDER'  => ['name ASC', 'id ASC'],
]) as $scanRow) {
    $scanDbId = (int) ($scanRow['id'] ?? 0);
    if ($scanDbId <= 0) continue;
    $visibleScanIds[] = $scanDbId;
    $scanMeta[$scanDbId] = [
        'name'    => (string) ($scanRow['name'] ?? ''),
        'scan_id' => (string) ($scanRow['scan_id'] ?? ''),
    ];
}

// Pagination params
$start   = max(0, (int) ($_GET['_start'] ?? 0));
$perPage = (int) ($_GET['_limit'] ?? 100);
$perPage = in_array($perPage, [25, 50, 100, 200], true) ? $perPage : 100;

// Lightweight count query — full dataset, for dashboard totals only
$counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
if ($visibleScanIds !== []) {
    foreach ($DB->request([
        'SELECT' => ['severity', 'severity_label'],
        'FROM'   => Vulnerability::getTable(),
        'WHERE'  => ['plugin_nessusglpi_scans_id' => $visibleScanIds, 'is_current' => 1],
    ]) as $cRow) {
        $sevKey = nessusglpi_consolidated_severity_key($cRow);
        $counts[$sevKey] = ($counts[$sevKey] ?? 0) + 1;
    }
}
$totalVulns = array_sum($counts);

// Paginated list query
$rows = [];
if ($visibleScanIds !== []) {
    foreach ($DB->request([
        'FROM'  => Vulnerability::getTable(),
        'WHERE' => ['plugin_nessusglpi_scans_id' => $visibleScanIds, 'is_current' => 1],
        'ORDER' => ['severity DESC', 'plugin_nessusglpi_scans_id ASC', 'plugin_name ASC', 'id DESC'],
        'LIMIT' => $perPage,
        'START' => $start,
    ]) as $row) {
        $host = new Host();
        $hostRow = [];
        if ($host->getFromDB((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0))) {
            $hostRow = $host->fields;
        }
        $sevKey = nessusglpi_consolidated_severity_key($row);
        $rows[] = [
            'data'   => $row,
            'host'   => $hostRow,
            'sevKey' => $sevKey,
        ];
    }
}

echo '<div class="card card-body nessus-vuln-page" data-nessus-vuln-page>';

echo '<div class="nessus-vuln-page__back">';
echo '<a class="nessus-btn-back" href="scan.php">' . nessusglpi_consolidated_icon('arrow-left') . '<span>' . Html::cleanInputText(__('Back')) . '</span></a>';
echo '</div>';

echo '<div class="nessus-vuln-page__hero">';
echo '<div class="nessus-vuln-page__title-group">';
echo '<h2 class="nessus-vuln-page__title">🛡️ ' . Html::cleanInputText(__('Consolidated vulnerabilities', 'nessusglpi')) . '</h2>';
echo '<span class="nessus-vuln-page__scan-pill">🏢 ' . Html::cleanInputText(implode(', ', $entityNames) ?: __('None')) . '</span>';
echo '</div>';
echo '</div>';

if ($totalVulns === 0) {
    echo '<div class="nessus-vuln-empty">';
    echo nessusglpi_consolidated_icon('inbox');
    echo '<h3>' . Html::cleanInputText(__('No vulnerabilities imported for the selected entities yet', 'nessusglpi')) . '</h3>';
    echo '<p>' . Html::cleanInputText(__('Import scans from the Tenable API to populate this view.', 'nessusglpi')) . '</p>';
    echo '</div>';
    echo '</div>';
    Html::footer();
    return;
}

echo '<div class="nessus-sev-dashboard">';
foreach (['critical', 'high', 'medium', 'low', 'info'] as $key) {
    echo '<button type="button" class="nessus-sev-card nessus-sev-card--' . $key . '" data-nessus-sev-card="' . $key . '" aria-pressed="false" title="' . Html::cleanInputText(sprintf(__('Filter by %s', 'nessusglpi'), nessusglpi_consolidated_severity_label($key))) . '">';
    echo '<span class="nessus-sev-card__icon">' . nessusglpi_consolidated_severity_icon($key) . '</span>';
    echo '<span class="nessus-sev-card__count">' . (int) $counts[$key] . '</span>';
    echo '<span class="nessus-sev-card__label">' . Html::cleanInputText(nessusglpi_consolidated_severity_label($key)) . '</span>';
    echo '</button>';
}
echo '</div>';

echo '<div class="nessus-sev-distribution">';
foreach (['critical', 'high', 'medium', 'low', 'info'] as $key) {
    $count = (int) $counts[$key];
    if ($count <= 0) continue;
    $width = ($count / $totalVulns) * 100;
    $widthStr = rtrim(rtrim(number_format(max($width, 4), 2, '.', ''), '0'), '.');
    echo '<div class="nessus-sev-distribution__segment nessus-sev-distribution__segment--' . $key . '" style="flex: ' . $widthStr . ' 0 0; min-width: 30px;" title="' . Html::cleanInputText(nessusglpi_consolidated_severity_label($key) . ': ' . $count) . '">' . $count . '</div>';
}
echo '</div>';

echo '<div class="nessus-vuln-page__total">' . sprintf(Html::cleanInputText(__('Total current vulnerabilities: %d', 'nessusglpi')), $totalVulns) . '</div>';

echo '<div class="nessus-vuln-page__toolbar">';
echo '<label class="nessus-vuln-page__search">';
echo '<input type="search" data-nessus-vuln-search autocomplete="off" spellcheck="false" placeholder="' . Html::cleanInputText(__('Search by name, host, scan…', 'nessusglpi')) . '">';
echo '</label>';
$pageFrom = $totalVulns > 0 ? $start + 1 : 0;
$pageTo   = min($start + count($rows), $totalVulns);
echo '<span class="nessus-vuln-page__meta">'
    . sprintf(Html::cleanInputText(__('%1$d–%2$d of %3$d', 'nessusglpi')), $pageFrom, $pageTo, $totalVulns)
    . '</span>';
echo '</div>';

echo '<div class="nessus-vuln-list" data-nessus-vuln-list>';

foreach ($rows as $r) {
    $row = $r['data'];
    $hostRow = $r['host'];
    $sevKey = $r['sevKey'];
    $hostMeta = nessusglpi_consolidated_host_link($row, $hostRow);
    $vulnName = (string) ($row['plugin_name'] ?? '');
    $scanDbId = (int) ($row['plugin_nessusglpi_scans_id'] ?? 0);
    $scanName = (string) ($scanMeta[$scanDbId]['name'] ?? '');
    $scanRefId = (string) ($scanMeta[$scanDbId]['scan_id'] ?? '');
    $cve = trim((string) ($row['cve'] ?? ''));

    $haystack = strtolower(trim($vulnName . ' ' . $hostMeta['label'] . ' ' . $scanName . ' ' . $scanRefId . ' ' . $cve));

    echo '<article class="nessus-vuln-row" data-nessus-vuln-row'
        . ' data-severity="' . Html::cleanInputText($sevKey) . '"'
        . ' data-ticket="0"'
        . ' data-haystack="' . Html::cleanInputText($haystack) . '"'
        . ' data-selected="false">';

    echo '<span class="nessus-vuln-row__check"><span class="nessus-vuln-row__check--placeholder"></span></span>';

    echo '<span class="nessus-sev-chip nessus-sev-chip--' . Html::cleanInputText($sevKey) . '">'
        . nessusglpi_consolidated_severity_icon($sevKey) . ' '
        . Html::cleanInputText(nessusglpi_consolidated_severity_label($sevKey))
        . '</span>';

    echo '<div class="nessus-vuln-row__body">';
    echo '<h3 class="nessus-vuln-row__title">' . Html::cleanInputText($vulnName !== '' ? $vulnName : __('Unnamed', 'nessusglpi')) . '</h3>';
    echo '<div class="nessus-vuln-row__meta">';
    echo '<span class="nessus-vuln-row__meta-item">🖥️ ';
    if ($hostMeta['href']) {
        echo '<a href="' . Html::cleanInputText($hostMeta['href']) . '">' . Html::cleanInputText($hostMeta['label']) . '</a>';
    } else {
        echo Html::cleanInputText($hostMeta['label']);
    }
    echo '</span>';
    if ($scanName !== '') {
        echo '<span class="nessus-vuln-row__meta-item">🔍 ' . Html::cleanInputText($scanName) . ($scanRefId !== '' ? ' · ' . Html::cleanInputText($scanRefId) : '') . '</span>';
    }
    if ($cve !== '') {
        echo '<span class="nessus-vuln-row__meta-item">🔗 ' . Html::cleanInputText($cve) . '</span>';
    }
    echo '</div>';
    echo '</div>';

    echo '<div class="nessus-vuln-row__actions"></div>';

    echo '</article>';
}

echo '</div>';

echo '<div class="nessus-vuln-empty" data-nessus-vuln-empty hidden>';
echo nessusglpi_consolidated_icon('search');
echo '<h3>' . Html::cleanInputText(__('No vulnerabilities match your filters', 'nessusglpi')) . '</h3>';
echo '<p>' . Html::cleanInputText(__('Try a different search or clear the severity filters.', 'nessusglpi')) . '</p>';
echo '</div>';

// Pagination bar
if ($totalVulns > $perPage || $start > 0) {
    $totalPages  = max(1, (int) ceil($totalVulns / $perPage));
    $currentPage = (int) floor($start / $perPage) + 1;
    $baseUrl     = Html::cleanInputText($_SERVER['PHP_SELF'] . '?_limit=' . $perPage);

    echo '<div class="nessus-pagination">';
    echo '<span class="nessus-pagination__info">' . sprintf(Html::cleanInputText(__('Page %1$d of %2$d', 'nessusglpi')), $currentPage, $totalPages) . '</span>';
    echo '<div class="nessus-pagination__nav">';
    if ($start > 0) {
        echo '<a class="nessus-pagination__btn" href="' . $baseUrl . '&_start=' . max(0, $start - $perPage) . '">&#8592; ' . Html::cleanInputText(__('Prev', 'nessusglpi')) . '</a>';
    } else {
        echo '<span class="nessus-pagination__btn nessus-pagination__btn--disabled">&#8592; ' . Html::cleanInputText(__('Prev', 'nessusglpi')) . '</span>';
    }
    if ($start + $perPage < $totalVulns) {
        echo '<a class="nessus-pagination__btn" href="' . $baseUrl . '&_start=' . ($start + $perPage) . '">' . Html::cleanInputText(__('Next', 'nessusglpi')) . ' &#8594;</a>';
    } else {
        echo '<span class="nessus-pagination__btn nessus-pagination__btn--disabled">' . Html::cleanInputText(__('Next', 'nessusglpi')) . ' &#8594;</span>';
    }
    echo '</div>';
    echo '<form method="get" class="nessus-pagination__per-page">';
    echo Html::hidden('_start', ['value' => 0]);
    echo '<label class="nessus-pagination__label">' . Html::cleanInputText(__('Per page:', 'nessusglpi'));
    echo '<select name="_limit" class="nessus-pagination__select" onchange="this.form.submit()">';
    foreach ([25, 50, 100, 200] as $opt) {
        echo '<option value="' . $opt . '"' . ($perPage === $opt ? ' selected' : '') . '>' . $opt . '</option>';
    }
    echo '</select></label>';
    echo '</form>';
    echo '</div>';
}

echo '</div>';

echo '<script src="' . Html::cleanInputText($assetsBase . '/js/vulnerabilities.js?v=' . $assetVersion) . '" defer></script>';

Html::footer();
