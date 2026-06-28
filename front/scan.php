<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Config;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncJobService;

include('../../../inc/includes.php');

Session::checkRight(Scan::$rightname, READ);

$syncResult = null;
$deleteResult = null;
$jobService = new SyncJobService();

if (isset($_POST['delete_selected_scans'])) {
    Session::checkRight(Scan::$rightname, UPDATE);

    $selectedIds = array_map('intval', (array) ($_POST['scan_ids'] ?? []));
    $selectedIds = array_values(array_filter($selectedIds, static fn (int $id): bool => $id > 0));

    if ($selectedIds === []) {
        $deleteResult = [
            'ok'      => false,
            'message' => __('Select at least one scan to delete.', 'nessusglpi'),
        ];
    } else {
        $deleted = Scan::deleteByIds($selectedIds);
        $deleteResult = [
            'ok'      => true,
            'message' => sprintf(__('Deleted %d scan(s).', 'nessusglpi'), $deleted),
        ];
    }
}

function nessusglpi_scan_status_bucket(string $status): string
{
    $value = strtolower(trim($status));
    if ($value === '' || $value === '-') {
        return 'unknown';
    }

    $buckets = [
        'success' => ['success', 'completed', 'imported', 'done', 'ok'],
        'running' => ['running', 'processing', 'pending', 'queued', 'in_progress'],
        'warning' => ['stopped', 'canceled', 'cancelled', 'paused', 'partial', 'skipped'],
        'danger'  => ['failed', 'error', 'aborted', 'crashed'],
        'muted'   => ['empty', 'never', 'no_data'],
    ];

    foreach ($buckets as $bucket => $values) {
        if (in_array($value, $values, true)) {
            return $bucket;
        }
    }

    return 'unknown';
}

function nessusglpi_scan_status_label(string $status): string
{
    $clean = trim($status);
    if ($clean === '') {
        return __('Never synced', 'nessusglpi');
    }

    return ucwords(str_replace(['_', '-'], ' ', strtolower($clean)));
}

function nessusglpi_scan_relative(string $value): string
{
    if ($value === '' || $value === '-') {
        return '';
    }

    $timestamp = is_numeric($value) ? (int) $value : strtotime($value);
    if (!is_int($timestamp) || $timestamp <= 0) {
        return '';
    }

    $diff = max(0, time() - $timestamp);
    if ($diff < 60) {
        return __('just now', 'nessusglpi');
    }
    if ($diff < 3600) {
        $minutes = (int) floor($diff / 60);
        return sprintf(_n('%d minute ago', '%d minutes ago', $minutes, 'nessusglpi'), $minutes);
    }
    if ($diff < 86400) {
        $hours = (int) floor($diff / 3600);
        return sprintf(_n('%d hour ago', '%d hours ago', $hours, 'nessusglpi'), $hours);
    }
    if ($diff < 2592000) {
        $days = (int) floor($diff / 86400);
        return sprintf(_n('%d day ago', '%d days ago', $days, 'nessusglpi'), $days);
    }
    if ($diff < 31536000) {
        $months = (int) floor($diff / 2592000);
        return sprintf(_n('%d month ago', '%d months ago', $months, 'nessusglpi'), $months);
    }
    $years = (int) floor($diff / 31536000);
    return sprintf(_n('%d year ago', '%d years ago', $years, 'nessusglpi'), $years);
}

function nessusglpi_scan_icon(string $name): string
{
    $icons = [
        'plus'    => '<path d="M12 5v14"/><path d="M5 12h14"/>',
        'search'  => '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
        'edit'    => '<path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
        'bug'     => '<path d="M8 2v2"/><path d="M16 2v2"/><rect x="6" y="6" width="12" height="14" rx="6"/><path d="M2 12h4"/><path d="M18 12h4"/>',
        'sync'    => '<path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/>',
        'external'=> '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><path d="m10 14 11-11"/>',
        'trash'   => '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
        'inbox'   => '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z"/>',
        'shield'  => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    ];
    $inner = $icons[$name] ?? '<circle cx="12" cy="12" r="10"/>';
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $inner . '</svg>';
}

Html::header(__('Nessus scans', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

global $DB, $CFG_GLPI;

$config = Config::getSingleton();
$nessusBaseUrl = rtrim((string) ($config->fields['api_url'] ?? ''), '/');
$entityCriteria = Scan::getVisibleScansCriteria();
$visibleEntityIds = Scan::getVisibleEntityIds();
$pendingJobs = $jobService->countPendingJobs($visibleEntityIds);
$openJobs = $jobService->countOpenJobs($visibleEntityIds);
$csrfToken = Session::getNewCSRFToken();

$rows = [];
foreach ($DB->request([
    'FROM'  => 'glpi_plugin_nessusglpi_scans',
    'WHERE' => $entityCriteria,
    'ORDER' => ['id DESC'],
]) as $row) {
    $rows[] = $row;
}

$totalScans = count($rows);
$assetsBase = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
$assetVersion = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';
$assetDir = __DIR__ . '/../public';
$cssVersion = $assetVersion . '-' . (@filemtime($assetDir . '/css/scan-list.css') ?: '0');
$jsVersion = $assetVersion . '-' . (@filemtime($assetDir . '/js/scan-list.js') ?: '0');

echo '<link rel="stylesheet" href="' . Html::cleanInputText($assetsBase . '/css/scan-list.css?v=' . $cssVersion) . '">';

$bulkFormId = 'nessusglpi-delete-scans-form';

$queueConfig = [
    'openJobs'        => (int) $openJobs,
    'url'             => $assetsBase . '/ajax/sync.queue.php',
    'csrf'            => $csrfToken,
    'idlePollMs'      => 15000,
    'checkedAt'       => date('Y-m-d H:i:s'),
    'i18n'            => [
        'startMessage'      => __('Monitoring %d queued synchronization job(s)…', 'nessusglpi'),
        'errorMessage'      => __('Could not contact the sync queue status endpoint. Will retry shortly.', 'nessusglpi'),
        'jobSuccess'        => __('Synchronization of “%s” finished.', 'nessusglpi'),
        'jobError'          => __('Synchronization of “%s” failed.', 'nessusglpi'),
        'queueIdle'         => __('Sync queue is idle.', 'nessusglpi'),
        'queueOpenSingular' => __('%d job in queue', 'nessusglpi'),
        'queueOpenPlural'   => __('%d jobs in queue', 'nessusglpi'),
        'queueWaitSingular' => __('%d job waiting', 'nessusglpi'),
        'queueWaitPlural'   => __('%d jobs waiting', 'nessusglpi'),
        'rowSyncing'        => __('Queued…', 'nessusglpi'),
        'rowSyncFailed'     => __('Sync failed', 'nessusglpi'),
    ],
];

echo '<div class="card card-body nessus-list-page" data-nessus-list-page'
    . ' data-nessus-bulk-form="' . Html::cleanInputText($bulkFormId) . '"'
    . ' data-nessus-queue="' . htmlspecialchars((string) json_encode($queueConfig), ENT_QUOTES) . '"'
    . '>';

echo '<div class="nessus-list-page__hero">';
echo '<div class="nessus-list-page__title-group">';
echo '<h2 class="nessus-list-page__title">' . Html::cleanInputText(__('Nessus scans', 'nessusglpi')) . '</h2>';
echo '<div class="nessus-list-page__stats">';
echo '<span class="nessus-stat-pill"><span class="nessus-stat-pill__dot"></span>'
    . sprintf(Html::cleanInputText(_n('%d scan', '%d scans', $totalScans, 'nessusglpi')), $totalScans)
    . '</span>';

$queuePillCount   = $openJobs > 0 ? $openJobs : $pendingJobs;
$queuePillVariant = $openJobs > 0 ? 'warn' : ($pendingJobs > 0 ? 'muted' : 'warn');
$queueLabelTpl    = $openJobs > 0
    ? _n('%d job in queue', '%d jobs in queue', max(1, $openJobs), 'nessusglpi')
    : _n('%d job waiting', '%d jobs waiting', max(1, $pendingJobs), 'nessusglpi');

echo '<span class="nessus-stat-pill nessus-stat-pill--' . Html::cleanInputText($queuePillVariant) . '"'
    . ' data-nessus-queue-pill'
    . ' data-nessus-queue-count="' . (int) $queuePillCount . '"'
    . ($queuePillCount === 0 ? ' hidden' : '')
    . '><span class="nessus-stat-pill__dot"></span>'
    . '<span data-nessus-queue-pill-label>'
    . sprintf(Html::cleanInputText($queueLabelTpl), $queuePillCount)
    . '</span></span>';
echo '</div>';
echo '</div>';

echo '<div class="nessus-list-page__actions">';
echo '<a class="nessus-btn-primary" href="scan.form.php">' . nessusglpi_scan_icon('plus') . '<span>' . Html::cleanInputText(__('Add')) . '</span></a>';
echo '<a class="nessus-btn-outline" href="scan.browser.php?source=' . Scan::SOURCE_NESSUS . '">' . nessusglpi_scan_icon('search') . '<span>' . Html::cleanInputText(__('Browse Nessus / Tenable VM scans', 'nessusglpi')) . '</span></a>';
echo '<a class="nessus-btn-outline" href="scan.browser.php?source=' . Scan::SOURCE_WAS . '">' . nessusglpi_scan_icon('search') . '<span>' . Html::cleanInputText(__('Browse Tenable WAS scans', 'nessusglpi')) . '</span></a>';
echo '<a class="nessus-btn-outline" href="scans.vulnerabilities.php">' . nessusglpi_scan_icon('shield') . '<span>' . Html::cleanInputText(__('Consolidated vulnerabilities', 'nessusglpi')) . '</span></a>';
echo '<a class="nessus-btn-outline" href="coverage.php">' . nessusglpi_scan_icon('shield') . '<span>' . Html::cleanInputText(__('VMs without Nessus', 'nessusglpi')) . '</span></a>';
echo '<a class="nessus-btn-outline" href="trends.php" title="' . Html::cleanInputText(__('Tendência de vulnerabilidades ao longo do tempo (30 dias a 18 meses)', 'nessusglpi')) . '">' . nessusglpi_scan_icon('chart') . '<span>' . Html::cleanInputText(__('Tendências', 'nessusglpi')) . '</span></a>';
echo '<a class="nessus-btn-outline" href="report.php" style="background:#041e42;border-color:#041e42;color:#26ff93;font-weight:700" title="Relatório executivo com índice de risco, severidades e tendências">'
    . nessusglpi_scan_icon('chart') . '<span>Relatório Executivo</span></a>';
echo '</div>';

echo '</div>';

if (is_array($syncResult)) {
    $class = !empty($syncResult['ok']) ? 'alert alert-success' : 'alert alert-danger';
    echo "<div class='${class}' role='alert'>" . Html::cleanInputText((string) ($syncResult['message'] ?? '')) . "</div>";
}

if (is_array($deleteResult)) {
    $class = !empty($deleteResult['ok']) ? 'alert alert-success' : 'alert alert-danger';
    echo "<div class='${class}' role='alert'>" . Html::cleanInputText((string) ($deleteResult['message'] ?? '')) . "</div>";
}

$statusBuckets = [];
foreach ($rows as $row) {
    $bucket = nessusglpi_scan_status_bucket((string) ($row['last_sync_status'] ?? ''));
    $statusBuckets[$bucket] = ($statusBuckets[$bucket] ?? 0) + 1;
}

echo '<div class="nessus-list-page__toolbar">';
echo '<input type="search" class="nessus-list-page__search" data-nessus-list-search autocomplete="off" spellcheck="false" placeholder="' . Html::cleanInputText(__('Search by name, scan ID or entity…', 'nessusglpi')) . '">';

echo '<select class="nessus-list-page__filter" data-nessus-list-filter aria-label="' . Html::cleanInputText(__('Filter by sync status', 'nessusglpi')) . '">';
echo '<option value="all">' . Html::cleanInputText(__('All statuses', 'nessusglpi')) . '</option>';
$filterOptions = [
    'success' => __('Synced', 'nessusglpi'),
    'running' => __('Running / pending', 'nessusglpi'),
    'warning' => __('Stopped / partial', 'nessusglpi'),
    'danger'  => __('Failed', 'nessusglpi'),
    'muted'   => __('Empty', 'nessusglpi'),
    'unknown' => __('Never synced', 'nessusglpi'),
];
foreach ($filterOptions as $bucket => $label) {
    $count = $statusBuckets[$bucket] ?? 0;
    if ($count === 0) {
        continue;
    }
    echo '<option value="' . Html::cleanInputText($bucket) . '">'
        . Html::cleanInputText($label) . ' (' . (int) $count . ')</option>';
}
echo '</select>';

echo '<label style="display:inline-flex;align-items:center;gap:6px;font-size:0.86rem;color:var(--nessus-muted);cursor:pointer;">';
echo '<input type="checkbox" data-nessus-master-check style="accent-color:var(--nessus-primary);">'
    . Html::cleanInputText(__('Select all visible', 'nessusglpi'));
echo '</label>';

echo '<button type="button" class="nessus-list-page__filter" data-nessus-list-clear hidden style="cursor:pointer;">'
    . Html::cleanInputText(__('Clear filters', 'nessusglpi')) . '</button>';

echo '<span class="nessus-list-page__meta">'
    . sprintf(
        Html::cleanInputText(__('Showing %1$s of %2$s', 'nessusglpi')),
        '<strong data-nessus-list-count>' . (int) $totalScans . '</strong>',
        '<span data-nessus-list-total>' . (int) $totalScans . '</span>'
    )
    . '</span>';
echo '</div>';

echo '<form id="' . Html::cleanInputText($bulkFormId) . '" method="post" action="">';
echo Html::hidden('_glpi_csrf_token', ['value' => $csrfToken]);
echo '</form>';

if ($totalScans === 0) {
    echo '<div class="nessus-list-page__empty">';
    echo nessusglpi_scan_icon('inbox');
    echo '<h3>' . Html::cleanInputText(__('No scans yet', 'nessusglpi')) . '</h3>';
    echo '<p>' . Html::cleanInputText(__('Browse the Tenable API to import your first scan, or add one manually.', 'nessusglpi')) . '</p>';
    echo '</div>';
} else {
    echo '<div class="nessus-list" data-nessus-list>';

    foreach ($rows as $row) {
        $scanId = (int) ($row['id'] ?? 0);
        $name = (string) ($row['name'] ?? '');
        $scanRefId = (string) ($row['scan_id'] ?? '');
        $rawSource = Scan::normalizeSource($row['scan_type'] ?? Scan::SOURCE_NESSUS);
        $sourceLabel = Scan::getSourceLabel($rawSource);
        $entityName = Dropdown::getDropdownName('glpi_entities', (int) ($row['entities_id'] ?? 0));
        $lastSyncStatus = (string) ($row['last_sync_status'] ?? '');
        $lastSyncBucket = nessusglpi_scan_status_bucket($lastSyncStatus);
        $lastSyncLabel = nessusglpi_scan_status_label($lastSyncStatus);
        $lastSyncRaw = (string) ($row['last_sync_at'] ?? '');
        $lastSyncRelative = nessusglpi_scan_relative($lastSyncRaw);
        $lastScanRaw = (string) ($row['last_scan_at'] ?? '');
        $lastScanRelative = nessusglpi_scan_relative($lastScanRaw);

        $sourceClass = $rawSource === Scan::SOURCE_WAS ? 'nessus-source-badge--was' : 'nessus-source-badge--vm';
        $sourceShort = $rawSource === Scan::SOURCE_WAS ? 'WAS' : 'VM';

        $haystack = strtolower(trim(
            $name . ' ' . $scanRefId . ' ' . $entityName . ' ' . $sourceLabel . ' ' . $lastSyncStatus . ' ' . $scanId
        ));

        echo '<article class="nessus-list-row" data-nessus-row'
            . ' data-nessus-scan-id="' . (int) $scanId . '"'
            . ' data-nessus-scan-name="' . Html::cleanInputText($name !== '' ? $name : ('#' . $scanId)) . '"'
            . ' data-status="' . Html::cleanInputText($lastSyncBucket) . '"'
            . ' data-haystack="' . Html::cleanInputText($haystack) . '"'
            . ' data-selected="false">';

        echo '<label class="nessus-list-row__check" title="' . Html::cleanInputText(__('Select scan', 'nessusglpi')) . '">';
        echo '<input type="checkbox" data-nessus-row-check name="scan_ids[]" value="' . (int) $scanId . '" form="' . Html::cleanInputText($bulkFormId) . '">';
        echo '</label>';

        echo '<div class="nessus-list-row__body">';
        echo '<div class="nessus-list-row__heading">';
        echo '<span class="nessus-source-badge ' . Html::cleanInputText($sourceClass) . '" title="' . Html::cleanInputText($sourceLabel) . '">'
            . Html::cleanInputText($sourceShort) . '</span>';
        echo '<h3 class="nessus-list-row__title"><a href="scan.form.php?id=' . (int) $scanId . '">'
            . Html::cleanInputText($name !== '' ? $name : __('Unnamed scan', 'nessusglpi'))
            . '</a></h3>';
        echo '<span class="nessus-status nessus-status--' . Html::cleanInputText($lastSyncBucket) . '" title="' . Html::cleanInputText($lastSyncStatus !== '' ? $lastSyncStatus : __('Never synced', 'nessusglpi')) . '">'
            . Html::cleanInputText($lastSyncLabel) . '</span>';
        echo '</div>';

        echo '<div class="nessus-list-row__meta">';
        echo '<span class="nessus-list-row__meta-item">#' . (int) $scanId . '</span>';
        if ($scanRefId !== '') {
            echo '<span class="nessus-list-row__meta-item">'
                . Html::cleanInputText(__('Scan ID', 'nessusglpi')) . ': '
                . '<code data-nessus-copy="' . Html::cleanInputText($scanRefId) . '" title="' . Html::cleanInputText(__('Copy scan ID', 'nessusglpi')) . '">'
                . Html::cleanInputText($scanRefId) . '</code></span>';
        }
        if ($entityName !== '') {
            echo '<span class="nessus-list-row__meta-item">' . Html::cleanInputText(__('Entity')) . ': '
                . Html::cleanInputText($entityName) . '</span>';
        }
        if ($lastScanRaw !== '' && $lastScanRaw !== '-') {
            echo '<span class="nessus-list-row__meta-item" title="' . Html::cleanInputText($lastScanRaw) . '">'
                . Html::cleanInputText(__('Scanned', 'nessusglpi')) . ' '
                . Html::cleanInputText($lastScanRelative !== '' ? $lastScanRelative : $lastScanRaw)
                . '</span>';
        }
        if ($lastSyncRaw !== '' && $lastSyncRaw !== '-') {
            echo '<span class="nessus-list-row__meta-item" title="' . Html::cleanInputText($lastSyncRaw) . '">'
                . Html::cleanInputText(__('Synced', 'nessusglpi')) . ' '
                . Html::cleanInputText($lastSyncRelative !== '' ? $lastSyncRelative : $lastSyncRaw)
                . '</span>';
        }
        echo '</div>';
        echo '</div>';

        echo '<div class="nessus-list-row__actions">';

        echo '<a class="nessus-btn-icon" title="' . Html::cleanInputText(__('Edit')) . '" aria-label="' . Html::cleanInputText(__('Edit')) . '" href="scan.form.php?id=' . (int) $scanId . '">'
            . nessusglpi_scan_icon('edit') . '</a>';

        echo '<a class="nessus-btn-icon" title="' . Html::cleanInputText(__('View vulnerabilities', 'nessusglpi')) . '" aria-label="' . Html::cleanInputText(__('View vulnerabilities', 'nessusglpi')) . '" href="scan.vulnerabilities.php?scan_id=' . (int) $scanId . '">'
            . nessusglpi_scan_icon('bug') . '</a>';

        if (
            $nessusBaseUrl !== ''
            && $lastSyncStatus === 'success'
            && $rawSource === Scan::SOURCE_NESSUS
            && $scanRefId !== ''
        ) {
            $nessusUrl = $nessusBaseUrl . '/#/scans/reports/' . rawurlencode($scanRefId) . '/scan-summary';
            echo '<a class="nessus-btn-icon" title="' . Html::cleanInputText(__('Open in Nessus', 'nessusglpi')) . '" aria-label="' . Html::cleanInputText(__('Open in Nessus', 'nessusglpi')) . '" target="_blank" rel="noopener noreferrer" href="' . Html::cleanInputText($nessusUrl) . '">'
                . nessusglpi_scan_icon('external') . '</a>';
        }

        echo '<form method="post" action="scan.sync.php" data-nessus-sync-form style="display:inline;"'
            . ' data-confirm-title="' . Html::cleanInputText(__('Queue scan synchronization?', 'nessusglpi')) . '"'
            . ' data-confirm-message="' . Html::cleanInputText(sprintf(__('A synchronization job will be queued for "%s".', 'nessusglpi'), $name !== '' ? $name : ('#' . $scanId))) . '"'
            . ' data-confirm-label="' . Html::cleanInputText(__('Queue', 'nessusglpi')) . '"'
            . ' data-cancel-label="' . Html::cleanInputText(__('Cancel')) . '">';
        echo Html::hidden('id', ['value' => (int) $scanId]);
        echo Html::hidden('_glpi_csrf_token', ['value' => $csrfToken]);
        echo '<button type="submit" name="sync_scan" class="nessus-btn-icon" title="' . Html::cleanInputText(__('Sync', 'nessusglpi')) . '" aria-label="' . Html::cleanInputText(__('Sync', 'nessusglpi')) . '">'
            . nessusglpi_scan_icon('sync') . '</button>';
        echo '</form>';

        echo '</div>';
        echo '</article>';
    }

    echo '</div>';

    echo '<div class="nessus-list-page__empty" data-nessus-list-empty hidden>';
    echo nessusglpi_scan_icon('search');
    echo '<h3>' . Html::cleanInputText(__('No scans match your filters', 'nessusglpi')) . '</h3>';
    echo '<p>' . Html::cleanInputText(__('Try a different search term or clear the status filter.', 'nessusglpi')) . '</p>';
    echo '</div>';
}

echo '<div class="nessus-selection-bar" data-nessus-selection-bar>';
echo '<span class="nessus-selection-bar__count"><strong data-nessus-selection-count>0</strong> '
    . Html::cleanInputText(__('selected', 'nessusglpi')) . '</span>';
echo '<span class="nessus-selection-bar__divider"></span>';
echo '<button type="button" class="is-danger" data-nessus-bulk-delete'
    . ' data-empty-text="' . Html::cleanInputText(__('Select at least one scan to delete.', 'nessusglpi')) . '"'
    . ' data-confirm-title="' . Html::cleanInputText(__('Delete selected scans?', 'nessusglpi')) . '"'
    . ' data-confirm-message="' . Html::cleanInputText(__('This will permanently remove %d scan(s) and all related plugin data (hosts, vulnerabilities, sync history, ticket links).', 'nessusglpi')) . '"'
    . ' data-confirm-label="' . Html::cleanInputText(__('Delete', 'nessusglpi')) . '"'
    . ' data-cancel-label="' . Html::cleanInputText(__('Cancel')) . '">'
    . nessusglpi_scan_icon('trash')
    . '<span>' . Html::cleanInputText(__('Delete selected', 'nessusglpi')) . '</span>'
    . '</button>';
echo '</div>';

echo '</div>';

echo '<script src="' . Html::cleanInputText($assetsBase . '/js/scan-list.js?v=' . $jsVersion) . '" defer></script>';

Html::footer();
