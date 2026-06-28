<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\ScanRun;

include('../../../inc/includes.php');

Session::checkRight(ScanRun::$rightname, READ);

global $DB, $CFG_GLPI;

$assetsBase   = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
$assetVersion = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';

$rows = [];
foreach ($DB->request([
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
    'WHERE' => Scan::getVisibleScansCriteria('glpi_plugin_nessusglpi_scans.entities_id'),
    'ORDER' => ['glpi_plugin_nessusglpi_scan_runs.id DESC'],
]) as $row) {
    $rows[] = $row;
}

$totalRuns = count($rows);

$statusBuckets = [];
foreach ($rows as $row) {
    $bucket = Scan::statusBucket((string) ($row['status'] ?? ''));
    $statusBuckets[$bucket] = ($statusBuckets[$bucket] ?? 0) + 1;
}

function nessusglpi_scanrun_icon(string $name): string
{
    $icons = [
        'search'  => '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
        'inbox'   => '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z"/>',
        'clock'   => '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
        'history' => '<path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/><polyline points="12 7 12 12 16 14"/>',
        'external'=> '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><path d="m10 14 11-11"/>',
    ];
    $inner = $icons[$name] ?? '<circle cx="12" cy="12" r="10"/>';
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $inner . '</svg>';
}

function nessusglpi_scanrun_duration(?string $startedAt, ?string $finishedAt): string
{
    if ($startedAt === null || $startedAt === '' || $startedAt === '-') {
        return '';
    }

    $start = strtotime($startedAt);
    if (!is_int($start) || $start <= 0) {
        return '';
    }

    if ($finishedAt === null || $finishedAt === '' || $finishedAt === '-') {
        return '';
    }

    $end = strtotime($finishedAt);
    if (!is_int($end) || $end <= 0 || $end < $start) {
        return '';
    }

    $diff = $end - $start;
    if ($diff < 60) {
        return sprintf(_n('%d second', '%d seconds', $diff, 'nessusglpi'), $diff);
    }

    if ($diff < 3600) {
        $minutes = (int) floor($diff / 60);
        $seconds = $diff % 60;
        if ($seconds === 0) {
            return sprintf(_n('%d minute', '%d minutes', $minutes, 'nessusglpi'), $minutes);
        }
        return sprintf(__('%dm %ds', 'nessusglpi'), $minutes, $seconds);
    }

    $hours = (int) floor($diff / 3600);
    $minutes = (int) floor(($diff % 3600) / 60);
    if ($minutes === 0) {
        return sprintf(_n('%d hour', '%d hours', $hours, 'nessusglpi'), $hours);
    }
    return sprintf(__('%dh %dm', 'nessusglpi'), $hours, $minutes);
}

Html::header(__('Scan history', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

echo '<link rel="stylesheet" href="' . Html::cleanInputText($assetsBase . '/css/scan-list.css?v=' . $assetVersion) . '">';

echo '<div class="card card-body nessus-list-page" data-nessus-list-page>';

echo '<div class="nessus-list-page__hero">';
echo '<div class="nessus-list-page__title-group">';
echo '<h2 class="nessus-list-page__title">' . Html::cleanInputText(__('Scan history', 'nessusglpi')) . '</h2>';
echo '<div class="nessus-list-page__stats">';
echo '<span class="nessus-stat-pill"><span class="nessus-stat-pill__dot"></span>'
    . sprintf(Html::cleanInputText(_n('%d run', '%d runs', $totalRuns, 'nessusglpi')), $totalRuns)
    . '</span>';
if (!empty($statusBuckets['running'])) {
    echo '<span class="nessus-stat-pill nessus-stat-pill--warn"><span class="nessus-stat-pill__dot"></span>'
        . sprintf(Html::cleanInputText(_n('%d running', '%d running', $statusBuckets['running'], 'nessusglpi')), $statusBuckets['running'])
        . '</span>';
}
if (!empty($statusBuckets['danger'])) {
    echo '<span class="nessus-stat-pill nessus-stat-pill--warn"><span class="nessus-stat-pill__dot"></span>'
        . sprintf(Html::cleanInputText(_n('%d failed', '%d failed', $statusBuckets['danger'], 'nessusglpi')), $statusBuckets['danger'])
        . '</span>';
}
echo '</div>';
echo '</div>';

echo '<div class="nessus-list-page__actions">';
echo '<a class="nessus-btn-outline" href="scan.php">'
    . nessusglpi_scanrun_icon('history') . '<span>'
    . Html::cleanInputText(__('Back to scans', 'nessusglpi')) . '</span></a>';
echo '</div>';
echo '</div>';

echo '<div class="nessus-list-page__toolbar">';
echo '<label class="nessus-list-page__search">';
echo '<span class="nessus-list-page__search-icon">' . nessusglpi_scanrun_icon('search') . '</span>';
echo '<input type="search" data-nessus-list-search autocomplete="off" spellcheck="false" placeholder="'
    . Html::cleanInputText(__('Search by scan name, scan ID or status…', 'nessusglpi')) . '">';
echo '</label>';

echo '<select class="nessus-list-page__filter" data-nessus-list-filter aria-label="'
    . Html::cleanInputText(__('Filter by status', 'nessusglpi')) . '">';
echo '<option value="all">' . Html::cleanInputText(__('All statuses', 'nessusglpi')) . '</option>';
foreach ([
    'success' => __('Success', 'nessusglpi'),
    'running' => __('Running / pending', 'nessusglpi'),
    'warning' => __('Partial / stopped', 'nessusglpi'),
    'danger'  => __('Failed', 'nessusglpi'),
    'muted'   => __('Empty', 'nessusglpi'),
    'unknown' => __('Other', 'nessusglpi'),
] as $bucket => $label) {
    $count = $statusBuckets[$bucket] ?? 0;
    if ($count === 0) {
        continue;
    }
    echo '<option value="' . Html::cleanInputText($bucket) . '">'
        . Html::cleanInputText($label) . ' (' . (int) $count . ')</option>';
}
echo '</select>';

echo '<button type="button" class="nessus-list-page__filter" data-nessus-list-clear hidden style="cursor:pointer;">'
    . Html::cleanInputText(__('Clear filters', 'nessusglpi')) . '</button>';

echo '<span class="nessus-list-page__meta">'
    . sprintf(
        Html::cleanInputText(__('Showing %1$s of %2$s', 'nessusglpi')),
        '<strong data-nessus-list-count>' . (int) $totalRuns . '</strong>',
        '<span data-nessus-list-total>' . (int) $totalRuns . '</span>'
    )
    . '</span>';
echo '</div>';

if ($totalRuns === 0) {
    echo '<div class="nessus-list-page__empty">';
    echo nessusglpi_scanrun_icon('inbox');
    echo '<h3>' . Html::cleanInputText(__('No scan runs yet', 'nessusglpi')) . '</h3>';
    echo '<p>' . Html::cleanInputText(__('Run a synchronization from the scan list to see history here.', 'nessusglpi')) . '</p>';
    echo '</div>';
} else {
    echo '<div class="nessus-list" data-nessus-list>';

    foreach ($rows as $row) {
        $runId        = (int) ($row['id'] ?? 0);
        $status       = (string) ($row['status'] ?? '');
        $bucket       = Scan::statusBucket($status);
        $label        = Scan::statusLabel($status);
        $startedAt    = (string) ($row['started_at'] ?? '');
        $finishedAt   = (string) ($row['finished_at'] ?? '');
        $startedRel   = Scan::relativeDate($startedAt);
        $duration     = nessusglpi_scanrun_duration($startedAt, $finishedAt);
        $scanName     = (string) ($row['scan_name'] ?? '-');
        $nessusScanId = (string) ($row['nessus_scan_id'] ?? '');
        $entityName   = Dropdown::getDropdownName('glpi_entities', (int) ($row['scan_entity_id'] ?? 0));
        $hosts        = (int) ($row['hosts_found'] ?? 0);
        $vulns        = (int) ($row['vulnerabilities_found'] ?? 0);
        $message      = trim((string) ($row['message'] ?? ''));

        $haystack = strtolower(trim(
            $scanName . ' ' . $nessusScanId . ' ' . $entityName . ' ' . $status . ' ' . $runId
        ));

        echo '<article class="nessus-list-row" data-nessus-row'
            . ' data-status="' . Html::cleanInputText($bucket) . '"'
            . ' data-haystack="' . Html::cleanInputText($haystack) . '"'
            . ' data-selected="false">';

        echo '<span class="nessus-list-row__check" aria-hidden="true"></span>';

        echo '<div class="nessus-list-row__body">';
        echo '<div class="nessus-list-row__heading">';
        echo '<span class="nessus-source-badge nessus-source-badge--vm" title="' . Html::cleanInputText(__('Scan run', 'nessusglpi')) . '">'
            . nessusglpi_scanrun_icon('history') . '</span>';
        echo '<h3 class="nessus-list-row__title">' . Html::cleanInputText($scanName);
        if ($nessusScanId !== '') {
            echo ' <span style="color:var(--nessus-muted); font-weight:400; font-size:0.86rem;">(' . Html::cleanInputText($nessusScanId) . ')</span>';
        }
        echo '</h3>';
        echo '<span class="nessus-status nessus-status--' . Html::cleanInputText($bucket) . '" title="'
            . Html::cleanInputText($status !== '' ? $status : __('Unknown', 'nessusglpi')) . '">'
            . Html::cleanInputText($label) . '</span>';
        echo '</div>';

        echo '<div class="nessus-list-row__meta">';
        echo '<span class="nessus-list-row__meta-item">#' . $runId . '</span>';

        if ($entityName !== '') {
            echo '<span class="nessus-list-row__meta-item">' . Html::cleanInputText(__('Entity')) . ': '
                . Html::cleanInputText($entityName) . '</span>';
        }

        if ($startedAt !== '' && $startedAt !== '-') {
            echo '<span class="nessus-list-row__meta-item" title="' . Html::cleanInputText($startedAt) . '">'
                . nessusglpi_scanrun_icon('clock')
                . ' ' . Html::cleanInputText(__('Started', 'nessusglpi')) . ' '
                . Html::cleanInputText($startedRel !== '' ? $startedRel : $startedAt) . '</span>';
        }

        if ($duration !== '') {
            echo '<span class="nessus-list-row__meta-item">'
                . Html::cleanInputText(__('Duration', 'nessusglpi')) . ': '
                . Html::cleanInputText($duration) . '</span>';
        }

        if ($hosts > 0) {
            echo '<span class="nessus-list-row__meta-item">'
                . sprintf(Html::cleanInputText(_n('%d host', '%d hosts', $hosts, 'nessusglpi')), $hosts)
                . '</span>';
        }

        if ($vulns > 0) {
            echo '<span class="nessus-list-row__meta-item">'
                . sprintf(Html::cleanInputText(_n('%d vulnerability', '%d vulnerabilities', $vulns, 'nessusglpi')), $vulns)
                . '</span>';
        }

        if ($message !== '') {
            echo '<span class="nessus-list-row__meta-item" title="' . Html::cleanInputText($message) . '">'
                . Html::cleanInputText(mb_strimwidth($message, 0, 80, '…'))
                . '</span>';
        }

        echo '</div>';
        echo '</div>';

        echo '<div class="nessus-list-row__actions"></div>';

        echo '</article>';
    }

    echo '</div>';

    echo '<div class="nessus-list-page__empty" data-nessus-list-empty hidden>';
    echo nessusglpi_scanrun_icon('search');
    echo '<h3>' . Html::cleanInputText(__('No runs match your filters', 'nessusglpi')) . '</h3>';
    echo '<p>' . Html::cleanInputText(__('Try a different search term or clear the status filter.', 'nessusglpi')) . '</p>';
    echo '</div>';
}

echo '</div>'; // /list-page

echo '<script src="' . Html::cleanInputText($assetsBase . '/js/scan-list.js?v=' . $assetVersion) . '" defer></script>';

Html::footer();
