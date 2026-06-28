<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\NessusClient;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\TenableWasClient;

include('../../../inc/includes.php');

Session::checkRight(Scan::$rightname, CREATE);

function nessusglpi_browser_nested_value(array $data, array $path)
{
    $current = $data;

    foreach ($path as $part) {
        if (!is_array($current) || !array_key_exists($part, $current)) {
            return null;
        }

        $current = $current[$part];
    }

    return $current;
}

function nessusglpi_browser_first_string(array $data, array $paths): string
{
    foreach ($paths as $path) {
        $value = nessusglpi_browser_nested_value($data, $path);
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        if (is_scalar($value) && trim((string) $value) !== '') {
            return trim((string) $value);
        }
    }

    return '';
}

function nessusglpi_browser_first_bool(array $data, array $paths): ?bool
{
    foreach ($paths as $path) {
        $value = nessusglpi_browser_nested_value($data, $path);
        if (is_bool($value)) {
            return $value;
        }
        if (!is_scalar($value)) {
            continue;
        }

        $normalized = strtolower(trim((string) $value));
        if (in_array($normalized, ['1', 'true', 'yes', 'enabled', 'active'], true)) {
            return true;
        }
        if (in_array($normalized, ['0', 'false', 'no', 'disabled', 'inactive'], true)) {
            return false;
        }
    }

    return null;
}

function nessusglpi_browser_pretty_date(string $value): string
{
    if ($value === '') {
        return '-';
    }

    if (is_numeric($value)) {
        $timestamp = (int) $value;
        if ($timestamp > 9999999999) {
            $timestamp = (int) floor($timestamp / 1000);
        }

        return $timestamp > 0 ? date('Y-m-d H:i:s', $timestamp) : $value;
    }

    $timestamp = strtotime($value);
    return $timestamp !== false ? date('Y-m-d H:i:s', $timestamp) : $value;
}

function nessusglpi_browser_relative_date(string $value): string
{
    if ($value === '' || $value === '-') {
        return '';
    }

    if (is_numeric($value)) {
        $timestamp = (int) $value;
        if ($timestamp > 9999999999) {
            $timestamp = (int) floor($timestamp / 1000);
        }
    } else {
        $timestamp = strtotime($value);
    }

    if (!is_int($timestamp) || $timestamp <= 0) {
        return '';
    }

    $diff = time() - $timestamp;
    if ($diff < 0) {
        $diff = 0;
    }

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

function nessusglpi_browser_item_id(array $row, array $paths): string
{
    return nessusglpi_browser_first_string($row, $paths);
}

function nessusglpi_browser_scan_id(array $row, string $source): string
{
    if ($source === Scan::SOURCE_NESSUS) {
        return nessusglpi_browser_item_id($row, [
            ['id'],
            ['scan_id'],
            ['uuid'],
            ['scan_uuid'],
        ]);
    }

    return nessusglpi_browser_item_id($row, [
        ['scan_id'],
        ['scan_uuid'],
        ['uuid'],
        ['id'],
    ]);
}

function nessusglpi_browser_config_id(array $row): string
{
    return nessusglpi_browser_item_id($row, [
        ['config_id'],
        ['config_uuid'],
        ['id'],
        ['uuid'],
    ]);
}

function nessusglpi_browser_name(array $row): string
{
    return nessusglpi_browser_first_string($row, [
        ['name'],
        ['scan_name'],
        ['title'],
        ['config_name'],
        ['application_name'],
        ['web_application_name'],
        ['target'],
        ['url'],
        ['application', 'name'],
        ['web_application', 'name'],
    ]);
}

function nessusglpi_browser_target(array $row): string
{
    return nessusglpi_browser_first_string($row, [
        ['url'],
        ['target'],
        ['application_url'],
        ['web_application_url'],
        ['asset', 'url'],
        ['application', 'url'],
        ['web_application', 'url'],
    ]);
}

function nessusglpi_browser_status(array $row): string
{
    $status = nessusglpi_browser_first_string($row, [
        ['status'],
        ['state'],
        ['scan_status'],
        ['scan', 'status'],
        ['last_scan', 'status'],
        ['latest_scan', 'status'],
    ]);
    if ($status !== '') {
        return $status;
    }

    $enabled = nessusglpi_browser_first_bool($row, [
        ['enabled'],
        ['is_enabled'],
        ['schedule', 'enabled'],
        ['settings', 'enabled'],
    ]);
    if ($enabled !== null) {
        return $enabled ? 'enabled' : 'disabled';
    }

    $disabled = nessusglpi_browser_first_bool($row, [
        ['disabled'],
        ['is_disabled'],
    ]);
    if ($disabled !== null) {
        return $disabled ? 'disabled' : 'enabled';
    }

    return '';
}

function nessusglpi_browser_date(array $row): string
{
    $value = nessusglpi_browser_first_string($row, [
        ['completed_at'],
        ['finished_at'],
        ['last_scan_time'],
        ['last_modification_date'],
        ['last_seen'],
        ['updated_at'],
        ['created_at'],
        ['start_time'],
        ['started_at'],
    ]);

    return nessusglpi_browser_pretty_date($value);
}

function nessusglpi_browser_raw_date(array $row): string
{
    return nessusglpi_browser_first_string($row, [
        ['completed_at'],
        ['finished_at'],
        ['last_scan_time'],
        ['last_modification_date'],
        ['last_seen'],
        ['updated_at'],
        ['created_at'],
        ['start_time'],
        ['started_at'],
    ]);
}

function nessusglpi_browser_form_url(string $source, string $scanId): string
{
    return 'scan.form.php?' . http_build_query([
        'scan_type' => $source,
        'scan_id'   => $scanId,
    ]);
}

function nessusglpi_browser_status_bucket(string $status): string
{
    $value = strtolower(trim($status));
    if ($value === '' || $value === '-') {
        return 'unknown';
    }

    $buckets = [
        'success' => ['completed', 'success', 'imported', 'published', 'finished', 'ok', 'done', 'enabled', '1', 'true', 'active'],
        'running' => ['running', 'processing', 'pending', 'queued', 'publishing', 'starting', 'resuming', 'in_progress', 'scanning'],
        'warning' => ['stopped', 'canceled', 'cancelled', 'paused', 'suspended', 'disabled', '0', 'false'],
        'danger'  => ['failed', 'error', 'aborted', 'crashed', 'rejected'],
        'muted'   => ['empty', 'new', 'draft', 'imported_no_data'],
    ];

    foreach ($buckets as $bucket => $values) {
        if (in_array($value, $values, true)) {
            return $bucket;
        }
    }

    return 'unknown';
}

function nessusglpi_browser_status_label(string $status): string
{
    $clean = trim($status);
    if ($clean === '') {
        return __('Unknown', 'nessusglpi');
    }

    return ucwords(str_replace(['_', '-'], ' ', strtolower($clean)));
}

function nessusglpi_browser_icon_copy(): string
{
    return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="5" width="9" height="9" rx="1.5"/><path d="M3 11V3.5A1.5 1.5 0 0 1 4.5 2H11"/></svg>';
}

function nessusglpi_browser_icon_arrow(): string
{
    return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3.5 8h9"/><path d="M9 4.5 12.5 8 9 11.5"/></svg>';
}

function nessusglpi_browser_icon_search(): string
{
    return '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7" cy="7" r="4.5"/><path d="m13 13-2.6-2.6"/></svg>';
}

function nessusglpi_browser_icon_empty(): string
{
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="10.5" cy="10.5" r="6.5"/><path d="m20 20-4.65-4.65"/><path d="M8 10.5h5"/></svg>';
}

function nessusglpi_browser_render_card(array $row, string $source, string $context): void
{
    $isWasConfig = $context === 'was_config';
    $isWasExecution = $context === 'was_execution';

    if ($isWasConfig) {
        $itemId = nessusglpi_browser_config_id($row);
    } else {
        $itemId = nessusglpi_browser_scan_id($row, $source);
    }

    $name = nessusglpi_browser_name($row);
    $target = nessusglpi_browser_target($row);
    $rawStatus = nessusglpi_browser_status($row);
    $statusBucket = nessusglpi_browser_status_bucket($rawStatus);
    $statusLabel = nessusglpi_browser_status_label($rawStatus);
    $showStatus = !$isWasConfig || $rawStatus !== '';
    $prettyDate = $isWasConfig ? '' : nessusglpi_browser_date($row);
    $rawDate = $isWasConfig ? '' : nessusglpi_browser_raw_date($row);
    $relativeDate = $isWasConfig ? '' : nessusglpi_browser_relative_date($rawDate);

    $haystack = strtolower(trim($name . ' ' . $target . ' ' . $itemId . ' ' . $rawStatus));

    $displayName = $name !== '' ? $name : __('Unnamed', 'nessusglpi');
    $displayTarget = $target !== '' ? $target : '';

    if ($isWasConfig) {
        $ctaHref = 'scan.browser.php?' . http_build_query([
            'source'    => Scan::SOURCE_WAS,
            'config_id' => $itemId,
        ]);
        $ctaLabel = __('View executions', 'nessusglpi');
    } else {
        $ctaHref = nessusglpi_browser_form_url($source, $itemId);
        $ctaLabel = __('Use this scan', 'nessusglpi');
    }

    echo '<article class="nessus-scan-card" data-nessus-card data-status="' . Html::cleanInputText($statusBucket) . '" data-haystack="' . Html::cleanInputText($haystack) . '">';

    echo '<div class="nessus-scan-card__header">';
    echo '<h3 class="nessus-scan-card__title">' . Html::cleanInputText($displayName) . '</h3>';
    if ($showStatus) {
        echo '<span class="nessus-status nessus-status--' . Html::cleanInputText($statusBucket) . '" title="' . Html::cleanInputText($rawStatus !== '' ? $rawStatus : __('No status reported', 'nessusglpi')) . '">'
            . Html::cleanInputText($statusLabel)
            . '</span>';
    }
    echo '</div>';

    if ($displayTarget !== '') {
        echo '<div class="nessus-scan-card__target">' . Html::cleanInputText($displayTarget) . '</div>';
    }

    echo '<div class="nessus-scan-card__meta">';
    if ($itemId !== '') {
        $idLabel = $isWasConfig ? __('Config ID', 'nessusglpi') : __('Scan ID', 'nessusglpi');
        echo '<span class="nessus-scan-card__id" data-nessus-copy="' . Html::cleanInputText($itemId) . '" title="' . Html::cleanInputText(sprintf(__('Copy %s', 'nessusglpi'), $idLabel)) . '" role="button" tabindex="0">';
        echo nessusglpi_browser_icon_copy();
        echo '<span>' . Html::cleanInputText($itemId) . '</span>';
        echo '</span>';
    } else {
        echo '<span class="nessus-scan-card__missing">' . Html::cleanInputText(__('Missing ID', 'nessusglpi')) . '</span>';
    }
    echo '</div>';

    echo '<div class="nessus-scan-card__footer">';

    if (!$isWasConfig && $prettyDate !== '' && $prettyDate !== '-') {
        $dateDisplay = $relativeDate !== '' ? $relativeDate : $prettyDate;
        echo '<span class="nessus-scan-card__date" title="' . Html::cleanInputText($prettyDate) . '">' . Html::cleanInputText($dateDisplay) . '</span>';
    } else {
        echo '<span class="nessus-scan-card__date">' . Html::cleanInputText($isWasConfig ? __('Configuration', 'nessusglpi') : '—') . '</span>';
    }

    if ($itemId !== '') {
        echo '<a class="nessus-scan-card__cta" href="' . Html::cleanInputText($ctaHref) . '">'
            . Html::cleanInputText($ctaLabel)
            . nessusglpi_browser_icon_arrow()
            . '</a>';
    } else {
        echo '<span class="nessus-scan-card__missing">' . Html::cleanInputText(__('Cannot use this entry', 'nessusglpi')) . '</span>';
    }

    echo '</div>';
    echo '</article>';
}

function nessusglpi_browser_render_grid(array $items, string $source, string $context): void
{
    if ($items === []) {
        echo '<div class="alert alert-warning nessus-alert-soft" role="alert">'
            . Html::cleanInputText(__('The API returned no results for this view.', 'nessusglpi'))
            . '</div>';
        return;
    }

    echo '<section data-nessus-browser class="nessus-browser">';

    $statusCounts = [];
    $totalItems = 0;
    foreach ($items as $item) {
        if (!is_array($item)) {
            continue;
        }
        $totalItems++;
        $rawStatus = nessusglpi_browser_status($item);
        if ($context === 'was_config' && $rawStatus === '') {
            continue;
        }
        $bucket = nessusglpi_browser_status_bucket($rawStatus);
        $statusCounts[$bucket] = ($statusCounts[$bucket] ?? 0) + 1;
    }

    echo '<div class="nessus-browser__toolbar">';
    echo '<label class="nessus-browser__search">';
    echo '<input type="search" data-nessus-search autocomplete="off" spellcheck="false" placeholder="' . Html::cleanInputText(__('Search by name, target or ID…', 'nessusglpi')) . '">';
    echo '</label>';

    if ($statusCounts !== []) {
        echo '<select class="nessus-browser__status-filter" data-nessus-status-filter aria-label="' . Html::cleanInputText(__('Filter by status', 'nessusglpi')) . '">';
        echo '<option value="all">' . Html::cleanInputText(__('All statuses', 'nessusglpi')) . '</option>';
        $statusOptions = [
            'success' => __('Completed', 'nessusglpi'),
            'running' => __('Running', 'nessusglpi'),
            'warning' => __('Stopped / disabled', 'nessusglpi'),
            'danger'  => __('Failed', 'nessusglpi'),
            'muted'   => __('Empty / draft', 'nessusglpi'),
            'unknown' => __('Unknown', 'nessusglpi'),
        ];
        foreach ($statusOptions as $bucket => $label) {
            $count = $statusCounts[$bucket] ?? 0;
            if ($count === 0) {
                continue;
            }
            echo '<option value="' . Html::cleanInputText($bucket) . '">'
                . Html::cleanInputText($label) . ' (' . (int) $count . ')'
                . '</option>';
        }
        echo '</select>';
    }

    echo '<button type="button" class="nessus-browser__clear" data-nessus-clear hidden>' . Html::cleanInputText(__('Clear filters', 'nessusglpi')) . '</button>';
    echo '<span class="nessus-browser__meta">'
        . sprintf(
            Html::cleanInputText(__('Showing %1$s of %2$s', 'nessusglpi')),
            '<strong data-nessus-count>' . (int) $totalItems . '</strong>',
            '<span data-nessus-total>' . (int) $totalItems . '</span>'
        )
        . '</span>';
    echo '</div>';

    echo '<div class="nessus-scan-grid" data-nessus-grid>';
    foreach ($items as $item) {
        if (!is_array($item)) {
            continue;
        }
        nessusglpi_browser_render_card($item, $source, $context);
    }
    echo '</div>';

    echo '<div class="nessus-empty" data-nessus-empty hidden>';
    echo nessusglpi_browser_icon_empty();
    echo '<h3>' . Html::cleanInputText(__('No results match your filters', 'nessusglpi')) . '</h3>';
    echo '<p>' . Html::cleanInputText(__('Try a different search term or clear the status filter.', 'nessusglpi')) . '</p>';
    echo '</div>';

    echo '</section>';
}

$source = Scan::normalizeSource($_GET['source'] ?? Scan::SOURCE_NESSUS);
$configId = trim((string) ($_GET['config_id'] ?? ''));
$error = null;
$items = [];

try {
    if ($source === Scan::SOURCE_WAS) {
        $client = new TenableWasClient();
        $items = $configId !== ''
            ? $client->getAllConfigScans($configId)
            : $client->getAllScanConfigs();
    } else {
        $items = (new NessusClient())->getAllScans();
    }
} catch (Throwable $e) {
    $error = $e->getMessage();
}

Html::header(__('Browse Tenable scans', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

global $CFG_GLPI;
$assetsBase = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
$assetVersion = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';
$assetDir = __DIR__ . '/../public';
$cssVersion = $assetVersion . '-' . (@filemtime($assetDir . '/css/scan-browser.css') ?: '0');
$jsVersion = $assetVersion . '-' . (@filemtime($assetDir . '/js/scan-browser.js') ?: '0');

echo '<link rel="stylesheet" href="' . Html::cleanInputText($assetsBase . '/css/scan-browser.css?v=' . $cssVersion) . '">';

echo '<div class="card card-body">';

echo '<div class="nessus-browser__header">';
echo '<h2 class="nessus-browser__title">'
    . Html::cleanInputText(__('Browse Tenable scans', 'nessusglpi'))
    . '</h2>';

echo '<div class="nessus-browser__source-tabs" role="tablist">';
$nessusHref = 'scan.browser.php?' . http_build_query(['source' => Scan::SOURCE_NESSUS]);
$wasHref = 'scan.browser.php?' . http_build_query(['source' => Scan::SOURCE_WAS]);
echo '<a href="' . Html::cleanInputText($nessusHref) . '" class="' . ($source === Scan::SOURCE_NESSUS ? 'is-active' : '') . '">'
    . Html::cleanInputText(__('Nessus / Tenable VM', 'nessusglpi'))
    . '</a>';
echo '<a href="' . Html::cleanInputText($wasHref) . '" class="' . ($source === Scan::SOURCE_WAS ? 'is-active' : '') . '">'
    . Html::cleanInputText(__('Tenable WAS', 'nessusglpi'))
    . '</a>';
echo '</div>';

echo '<a class="btn btn-outline-secondary btn-sm" href="scan.php">&larr; ' . Html::cleanInputText(__('Back')) . '</a>';
echo '</div>';

if ($error !== null) {
    echo '<div class="alert alert-danger nessus-alert-soft" role="alert">' . Html::cleanInputText($error) . '</div>';
} elseif ($source === Scan::SOURCE_WAS && $configId === '') {
    echo '<h3 class="h4">' . Html::cleanInputText(__('WAS configurations', 'nessusglpi')) . '</h3>';
    nessusglpi_browser_render_grid($items, $source, 'was_config');
} else {
    if ($source === Scan::SOURCE_WAS) {
        $backHref = 'scan.browser.php?' . http_build_query(['source' => Scan::SOURCE_WAS]);
        echo '<div class="nessus-browser__back"><a class="btn btn-outline-secondary btn-sm" href="' . Html::cleanInputText($backHref) . '">&larr; ' . Html::cleanInputText(__('Back to WAS configurations', 'nessusglpi')) . '</a></div>';
        echo '<h3 class="h4">' . Html::cleanInputText(__('WAS scan executions', 'nessusglpi')) . '</h3>';
        nessusglpi_browser_render_grid($items, $source, 'was_execution');
    } else {
        echo '<h3 class="h4">' . Html::cleanInputText(__('Nessus / Tenable VM scans', 'nessusglpi')) . '</h3>';
        nessusglpi_browser_render_grid($items, $source, 'scan');
    }
}

echo '</div>';

echo '<script src="' . Html::cleanInputText($assetsBase . '/js/scan-browser.js?v=' . $jsVersion) . '" defer></script>';

Html::footer();
