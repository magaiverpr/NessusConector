<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Host;
use GlpiPlugin\Nessusglpi\Scan;

include('../../../inc/includes.php');

Session::checkRight(Host::$rightname, READ);

$deleteResult = null;
$csrfToken = Session::getNewCSRFToken();

if (isset($_POST['delete_selected_hosts'])) {
    Session::checkRight(Host::$rightname, UPDATE);
    // CSRF is validated by GLPI 11's kernel (CheckCsrfListener) before this script runs.

    $selectedIds = array_map('intval', (array) ($_POST['host_ids'] ?? []));
    $selectedIds = array_values(array_filter($selectedIds, static fn (int $id): bool => $id > 0));

    if ($selectedIds === []) {
        $deleteResult = [
            'ok'      => false,
            'message' => __('Select at least one imported host to delete.', 'nessusglpi'),
        ];
    } else {
        $deleted = Host::deleteByIds($selectedIds);
        $deleteResult = [
            'ok'      => true,
            'message' => sprintf(__('Deleted %d imported host(s).', 'nessusglpi'), $deleted),
        ];
    }
}

function nessusglpi_host_match_bucket(string $status): string
{
    $value = strtolower(trim($status));
    return match ($value) {
        'matched', 'ok', 'success' => 'success',
        'failed', 'error', 'rejected' => 'danger',
        'pending', '' => 'warning',
        default => 'muted',
    };
}

function nessusglpi_host_match_label(string $status): string
{
    $clean = trim($status);
    if ($clean === '') {
        return __('Pending', 'nessusglpi');
    }

    return ucwords(str_replace(['_', '-'], ' ', strtolower($clean)));
}

function nessusglpi_host_label(array $row): string
{
    $fqdn = trim((string) ($row['fqdn'] ?? ''));
    if ($fqdn !== '') {
        return $fqdn;
    }
    $hostname = trim((string) ($row['hostname'] ?? ''));
    if ($hostname !== '') {
        return $hostname;
    }
    $ip = trim((string) ($row['ip'] ?? ''));
    if ($ip !== '') {
        return $ip;
    }
    return __('Unknown host', 'nessusglpi');
}

function nessusglpi_host_icon(string $name): string
{
    $icons = [
        'search'  => '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
        'trash'   => '<polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>',
        'inbox'   => '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z"/>',
        'server'  => '<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/>',
        'external'=> '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><path d="m10 14 11-11"/>',
    ];
    $inner = $icons[$name] ?? '<circle cx="12" cy="12" r="10"/>';
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $inner . '</svg>';
}

global $DB, $CFG_GLPI;

$assetsBase   = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
$assetVersion = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';

$rows = [];
foreach ($DB->request([
    'SELECT' => [
        'glpi_plugin_nessusglpi_hosts.*',
        'glpi_plugin_nessusglpi_scans.name AS scan_name',
        'glpi_plugin_nessusglpi_scans.scan_id AS nessus_scan_id',
    ],
    'FROM'   => Host::getTable(),
    'LEFT JOIN' => [
        'glpi_plugin_nessusglpi_scans' => [
            'FKEY' => [
                'glpi_plugin_nessusglpi_hosts' => 'plugin_nessusglpi_scans_id',
                'glpi_plugin_nessusglpi_scans' => 'id',
            ],
        ],
    ],
    'ORDER'  => ['glpi_plugin_nessusglpi_hosts.id DESC'],
]) as $row) {
    $rows[] = $row;
}

$totalHosts = count($rows);

$matchBuckets = [];
foreach ($rows as $row) {
    $bucket = nessusglpi_host_match_bucket((string) ($row['match_status'] ?? ''));
    $matchBuckets[$bucket] = ($matchBuckets[$bucket] ?? 0) + 1;
}

$canUpdate = Session::haveRight(Host::$rightname, UPDATE) > 0;
$bulkFormId = 'nessusglpi-delete-hosts-form';

Html::header(__('Imported hosts', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

echo '<link rel="stylesheet" href="' . Html::cleanInputText($assetsBase . '/css/scan-list.css?v=' . $assetVersion) . '">';

echo '<div class="card card-body nessus-list-page" data-nessus-list-page'
    . ' data-nessus-bulk-form="' . Html::cleanInputText($bulkFormId) . '">';

echo '<div class="nessus-list-page__hero">';
echo '<div class="nessus-list-page__title-group">';
echo '<h2 class="nessus-list-page__title">' . Html::cleanInputText(__('Imported hosts', 'nessusglpi')) . '</h2>';
echo '<div class="nessus-list-page__stats">';
echo '<span class="nessus-stat-pill"><span class="nessus-stat-pill__dot"></span>'
    . sprintf(Html::cleanInputText(_n('%d host', '%d hosts', $totalHosts, 'nessusglpi')), $totalHosts)
    . '</span>';
if (!empty($matchBuckets['warning'])) {
    echo '<span class="nessus-stat-pill nessus-stat-pill--warn"><span class="nessus-stat-pill__dot"></span>'
        . sprintf(Html::cleanInputText(_n('%d pending', '%d pending', $matchBuckets['warning'], 'nessusglpi')), $matchBuckets['warning'])
        . '</span>';
}
if (!empty($matchBuckets['danger'])) {
    echo '<span class="nessus-stat-pill nessus-stat-pill--warn"><span class="nessus-stat-pill__dot"></span>'
        . sprintf(Html::cleanInputText(_n('%d failed', '%d failed', $matchBuckets['danger'], 'nessusglpi')), $matchBuckets['danger'])
        . '</span>';
}
echo '</div>';
echo '</div>';
echo '</div>';

if (is_array($deleteResult)) {
    $class = !empty($deleteResult['ok']) ? 'alert alert-success' : 'alert alert-danger';
    echo "<div class='${class}' role='alert'>" . Html::cleanInputText((string) ($deleteResult['message'] ?? '')) . '</div>';
}

echo '<div class="nessus-list-page__toolbar">';
echo '<label class="nessus-list-page__search">';
echo '<span class="nessus-list-page__search-icon">' . nessusglpi_host_icon('search') . '</span>';
echo '<input type="search" data-nessus-list-search autocomplete="off" spellcheck="false" placeholder="'
    . Html::cleanInputText(__('Search by hostname, FQDN, IP or scan…', 'nessusglpi')) . '">';
echo '</label>';

echo '<select class="nessus-list-page__filter" data-nessus-list-filter aria-label="'
    . Html::cleanInputText(__('Filter by match status', 'nessusglpi')) . '">';
echo '<option value="all">' . Html::cleanInputText(__('All statuses', 'nessusglpi')) . '</option>';
foreach ([
    'success' => __('Matched', 'nessusglpi'),
    'warning' => __('Pending', 'nessusglpi'),
    'danger'  => __('Failed', 'nessusglpi'),
    'muted'   => __('Other', 'nessusglpi'),
] as $bucket => $label) {
    $count = $matchBuckets[$bucket] ?? 0;
    if ($count === 0) {
        continue;
    }
    echo '<option value="' . Html::cleanInputText($bucket) . '">'
        . Html::cleanInputText($label) . ' (' . (int) $count . ')</option>';
}
echo '</select>';

if ($canUpdate) {
    echo '<label style="display:inline-flex;align-items:center;gap:6px;font-size:0.86rem;color:var(--nessus-muted);cursor:pointer;">';
    echo '<input type="checkbox" data-nessus-master-check style="accent-color:var(--nessus-primary);">'
        . Html::cleanInputText(__('Select all visible', 'nessusglpi'));
    echo '</label>';
}

echo '<button type="button" class="nessus-list-page__filter" data-nessus-list-clear hidden style="cursor:pointer;">'
    . Html::cleanInputText(__('Clear filters', 'nessusglpi')) . '</button>';

echo '<span class="nessus-list-page__meta">'
    . sprintf(
        Html::cleanInputText(__('Showing %1$s of %2$s', 'nessusglpi')),
        '<strong data-nessus-list-count>' . (int) $totalHosts . '</strong>',
        '<span data-nessus-list-total>' . (int) $totalHosts . '</span>'
    )
    . '</span>';
echo '</div>';

echo '<form id="' . Html::cleanInputText($bulkFormId) . '" method="post" action="">';
echo Html::hidden('_glpi_csrf_token', ['value' => $csrfToken]);
echo '</form>';

if ($totalHosts === 0) {
    echo '<div class="nessus-list-page__empty">';
    echo nessusglpi_host_icon('inbox');
    echo '<h3>' . Html::cleanInputText(__('No imported hosts yet', 'nessusglpi')) . '</h3>';
    echo '<p>' . Html::cleanInputText(__('Hosts will appear here after a successful synchronization.', 'nessusglpi')) . '</p>';
    echo '</div>';
} else {
    echo '<div class="nessus-list" data-nessus-list>';

    foreach ($rows as $row) {
        $hostId       = (int) ($row['id'] ?? 0);
        $hostLabel    = nessusglpi_host_label($row);
        $matchStatus  = (string) ($row['match_status'] ?? '');
        $matchBucket  = nessusglpi_host_match_bucket($matchStatus);
        $matchLabel   = nessusglpi_host_match_label($matchStatus);
        $scanName     = (string) ($row['scan_name'] ?? '');
        $nessusScanId = (string) ($row['nessus_scan_id'] ?? '');

        $linkedAssetHtml = '';
        if (!empty($row['itemtype']) && (int) ($row['items_id'] ?? 0) > 0) {
            $item = getItemForItemtype((string) $row['itemtype']);
            if ($item instanceof CommonDBTM && $item->getFromDB((int) $row['items_id'])) {
                $itemName = method_exists($item, 'getName') ? (string) $item->getName() : (string) ($item->fields['name'] ?? '');
                if ($itemName === '') {
                    $itemName = (string) $row['itemtype'] . ' #' . (int) $row['items_id'];
                }
                $linkedAssetHtml = '<a class="nessus-list-row__asset" href="' . Html::cleanInputText($item->getLinkURL()) . '">'
                    . nessusglpi_host_icon('external') . '<span>' . Html::cleanInputText($itemName) . '</span></a>';
            } else {
                $linkedAssetHtml = '<span class="nessus-list-row__asset">'
                    . Html::cleanInputText((string) $row['itemtype']) . ' #' . (int) $row['items_id'] . '</span>';
            }
        }

        $haystack = strtolower(trim(
            $hostLabel . ' ' . ($row['hostname'] ?? '') . ' ' . ($row['fqdn'] ?? '') . ' ' . ($row['ip'] ?? '')
            . ' ' . $scanName . ' ' . $nessusScanId . ' ' . $matchStatus . ' ' . $hostId
        ));

        echo '<article class="nessus-list-row" data-nessus-row'
            . ' data-status="' . Html::cleanInputText($matchBucket) . '"'
            . ' data-haystack="' . Html::cleanInputText($haystack) . '"'
            . ' data-selected="false">';

        if ($canUpdate) {
            echo '<label class="nessus-list-row__check" title="' . Html::cleanInputText(__('Select host', 'nessusglpi')) . '">';
            echo '<input type="checkbox" data-nessus-row-check name="host_ids[]" value="' . $hostId . '" form="' . Html::cleanInputText($bulkFormId) . '">';
            echo '</label>';
        } else {
            echo '<span class="nessus-list-row__check" aria-hidden="true"></span>';
        }

        echo '<div class="nessus-list-row__body">';
        echo '<div class="nessus-list-row__heading">';
        echo '<span class="nessus-source-badge nessus-source-badge--vm" title="' . Html::cleanInputText(__('Imported host', 'nessusglpi')) . '">'
            . nessusglpi_host_icon('server') . '</span>';
        echo '<h3 class="nessus-list-row__title">' . Html::cleanInputText($hostLabel) . '</h3>';
        echo '<span class="nessus-status nessus-status--' . Html::cleanInputText($matchBucket) . '" title="'
            . Html::cleanInputText($matchStatus !== '' ? $matchStatus : __('Pending', 'nessusglpi')) . '">'
            . Html::cleanInputText($matchLabel) . '</span>';
        echo '</div>';

        echo '<div class="nessus-list-row__meta">';
        echo '<span class="nessus-list-row__meta-item">#' . $hostId . '</span>';

        $hostname = trim((string) ($row['hostname'] ?? ''));
        if ($hostname !== '' && $hostname !== $hostLabel) {
            echo '<span class="nessus-list-row__meta-item">'
                . Html::cleanInputText(__('Hostname', 'nessusglpi')) . ': '
                . Html::cleanInputText($hostname) . '</span>';
        }

        $fqdn = trim((string) ($row['fqdn'] ?? ''));
        if ($fqdn !== '' && $fqdn !== $hostLabel) {
            echo '<span class="nessus-list-row__meta-item">FQDN: '
                . Html::cleanInputText($fqdn) . '</span>';
        }

        $ip = trim((string) ($row['ip'] ?? ''));
        if ($ip !== '') {
            echo '<span class="nessus-list-row__meta-item">IP: <code data-nessus-copy="' . Html::cleanInputText($ip)
                . '" title="' . Html::cleanInputText(__('Copy IP', 'nessusglpi')) . '">'
                . Html::cleanInputText($ip) . '</code></span>';
        }

        if ($scanName !== '') {
            echo '<span class="nessus-list-row__meta-item">'
                . Html::cleanInputText(__('Scan', 'nessusglpi')) . ': '
                . Html::cleanInputText($scanName);
            if ($nessusScanId !== '') {
                echo ' <code data-nessus-copy="' . Html::cleanInputText($nessusScanId) . '" title="'
                    . Html::cleanInputText(__('Copy scan ID', 'nessusglpi')) . '">'
                    . Html::cleanInputText($nessusScanId) . '</code>';
            }
            echo '</span>';
        }

        if ($linkedAssetHtml !== '') {
            echo '<span class="nessus-list-row__meta-item">'
                . Html::cleanInputText(__('Linked asset', 'nessusglpi')) . ': '
                . $linkedAssetHtml
                . '</span>';
        }

        echo '</div>';
        echo '</div>';

        echo '<div class="nessus-list-row__actions">';
        if (!empty($row['itemtype']) && (int) ($row['items_id'] ?? 0) > 0) {
            $item = getItemForItemtype((string) $row['itemtype']);
            if ($item instanceof CommonDBTM && $item->getFromDB((int) $row['items_id'])) {
                echo '<a class="nessus-btn-icon" title="' . Html::cleanInputText(__('Open linked asset', 'nessusglpi')) . '"'
                    . ' aria-label="' . Html::cleanInputText(__('Open linked asset', 'nessusglpi')) . '"'
                    . ' href="' . Html::cleanInputText($item->getLinkURL()) . '">'
                    . nessusglpi_host_icon('external') . '</a>';
            }
        }
        echo '</div>';

        echo '</article>';
    }

    echo '</div>';

    echo '<div class="nessus-list-page__empty" data-nessus-list-empty hidden>';
    echo nessusglpi_host_icon('search');
    echo '<h3>' . Html::cleanInputText(__('No hosts match your filters', 'nessusglpi')) . '</h3>';
    echo '<p>' . Html::cleanInputText(__('Try a different search term or clear the status filter.', 'nessusglpi')) . '</p>';
    echo '</div>';
}

if ($canUpdate) {
    echo '<div class="nessus-selection-bar" data-nessus-selection-bar>';
    echo '<span class="nessus-selection-bar__count"><strong data-nessus-selection-count>0</strong> '
        . Html::cleanInputText(__('selected', 'nessusglpi')) . '</span>';
    echo '<span class="nessus-selection-bar__divider"></span>';
    echo '<button type="button" class="is-danger" data-nessus-bulk-delete'
        . ' data-bulk-action="delete_selected_hosts"'
        . ' data-empty-text="' . Html::cleanInputText(__('Select at least one imported host to delete.', 'nessusglpi')) . '"'
        . ' data-confirm-title="' . Html::cleanInputText(__('Delete selected hosts?', 'nessusglpi')) . '"'
        . ' data-confirm-message="' . Html::cleanInputText(__('This will permanently remove %d imported host(s) and their vulnerability records.', 'nessusglpi')) . '"'
        . ' data-confirm-label="' . Html::cleanInputText(__('Delete', 'nessusglpi')) . '"'
        . ' data-cancel-label="' . Html::cleanInputText(__('Cancel')) . '">'
        . nessusglpi_host_icon('trash')
        . '<span>' . Html::cleanInputText(__('Delete selected', 'nessusglpi')) . '</span>'
        . '</button>';
    echo '</div>';
}

echo '</div>'; // /list-page

echo '<script src="' . Html::cleanInputText($assetsBase . '/js/scan-list.js?v=' . $assetVersion) . '" defer></script>';

Html::footer();
