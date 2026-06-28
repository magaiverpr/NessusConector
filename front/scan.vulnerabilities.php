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

function nessusglpi_vuln_severity_key(array $row): string
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

function nessusglpi_vuln_severity_label(string $key): string
{
    return match ($key) {
        'critical' => __('Critical', 'nessusglpi'),
        'high' => __('High', 'nessusglpi'),
        'medium' => __('Medium', 'nessusglpi'),
        'low' => __('Low', 'nessusglpi'),
        default => __('Info', 'nessusglpi'),
    };
}

function nessusglpi_vuln_severity_icon(string $key): string
{
    return match ($key) {
        'critical' => '💀',
        'high' => '🚨',
        'medium' => '⚠️',
        'low' => '🟡',
        default => '🔵',
    };
}

function nessusglpi_vuln_icon(string $name): string
{
    $icons = [
        'search'  => '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
        'eye'     => '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
        'ticket' => '<path d="M3 7v3a2 2 0 1 1 0 4v3a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-3a2 2 0 1 1 0-4V7a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2Z"/><path d="M9 5v14"/>',
        'plus'    => '<path d="M12 5v14"/><path d="M5 12h14"/>',
        'check'   => '<path d="M20 6 9 17l-5-5"/>',
        'shield'  => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'arrow-left' => '<path d="M19 12H5"/><path d="m12 19-7-7 7-7"/>',
        'inbox'   => '<polyline points="22 12 16 12 14 15 10 15 8 12 2 12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z"/>',
    ];
    $inner = $icons[$name] ?? '<circle cx="12" cy="12" r="10"/>';
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $inner . '</svg>';
}

function nessusglpi_vuln_host_label(array $hostRow): string
{
    $fqdn = trim((string) ($hostRow['fqdn'] ?? ''));
    if ($fqdn !== '') return $fqdn;
    $hostname = trim((string) ($hostRow['hostname'] ?? ''));
    if ($hostname !== '') return $hostname;
    $ip = trim((string) ($hostRow['ip'] ?? ''));
    if ($ip !== '') return $ip;
    return __('Unknown host', 'nessusglpi');
}

function nessusglpi_vuln_host_link(array $row, array $hostRow): array
{
    $label = nessusglpi_vuln_host_label($hostRow);
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

function nessusglpi_vuln_existing_ticket(array $vulnerabilityRow): ?array
{
    return Vulnerability::getLinkedTicketData($vulnerabilityRow);
}

Html::header(__('Scan vulnerabilities', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

global $DB, $CFG_GLPI;

$assetsBase = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
$assetVersion = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';
$assetDir = __DIR__ . '/../public';
$cssVersion = $assetVersion . '-' . (@filemtime($assetDir . '/css/vulnerabilities.css') ?: '0');
$jsVersion  = $assetVersion . '-' . (@filemtime($assetDir . '/js/vulnerabilities.js') ?: '0');

echo '<link rel="stylesheet" href="' . Html::cleanInputText($assetsBase . '/css/vulnerabilities.css?v=' . $cssVersion) . '">';

// Pagination params
$start   = max(0, (int) ($_GET['_start'] ?? 0));
$perPage = (int) ($_GET['_limit'] ?? 100);
$perPage = in_array($perPage, [25, 50, 100, 200], true) ? $perPage : 100;

// Host filter — only list hosts that actually have current findings for this scan.
$hostFilter = (int) ($_GET['host_id'] ?? 0);
$hostCounts = [];
foreach ($DB->request([
    'SELECT' => ['plugin_nessusglpi_hosts_id'],
    'FROM'   => GlpiPlugin\Nessusglpi\Vulnerability::getTable(),
    'WHERE'  => ['plugin_nessusglpi_scans_id' => $scanId, 'is_current' => 1],
]) as $hAgg) {
    $hid = (int) ($hAgg['plugin_nessusglpi_hosts_id'] ?? 0);
    if ($hid > 0) {
        $hostCounts[$hid] = ($hostCounts[$hid] ?? 0) + 1;
    }
}
$hostLabels = [];
foreach (array_keys($hostCounts) as $hid) {
    $h = new Host();
    $hostLabels[$hid] = $h->getFromDB($hid) ? nessusglpi_vuln_host_label($h->fields) : ('#' . $hid);
}
uasort($hostLabels, static fn($a, $b) => strcasecmp((string) $a, (string) $b));
if ($hostFilter > 0 && !isset($hostCounts[$hostFilter])) {
    $hostFilter = 0; // chosen host has no current findings — fall back to all
}

// Scope applied to both the dashboard counts and the list. When a host is
// selected the dashboard recomputes for that host only.
$scopeWhere = ['plugin_nessusglpi_scans_id' => $scanId, 'is_current' => 1];
if ($hostFilter > 0) {
    $scopeWhere['plugin_nessusglpi_hosts_id'] = $hostFilter;
}

// Lightweight count query — for dashboard totals (scoped to host filter if set)
$counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
foreach ($DB->request([
    'SELECT' => ['severity', 'severity_label'],
    'FROM'   => GlpiPlugin\Nessusglpi\Vulnerability::getTable(),
    'WHERE'  => $scopeWhere,
]) as $cRow) {
    $sevKey = nessusglpi_vuln_severity_key($cRow);
    $counts[$sevKey] = ($counts[$sevKey] ?? 0) + 1;
}
$totalVulns = array_sum($counts);

// Paginated list query
$rows = [];
foreach ($DB->request([
    'FROM'  => GlpiPlugin\Nessusglpi\Vulnerability::getTable(),
    'WHERE' => $scopeWhere,
    'ORDER' => ['severity DESC', 'plugin_name ASC', 'id DESC'],
    'LIMIT' => $perPage,
    'START' => $start,
]) as $row) {
    $host = new Host();
    $hostRow = [];
    if ($host->getFromDB((int) ($row['plugin_nessusglpi_hosts_id'] ?? 0))) {
        $hostRow = $host->fields;
    }
    $sevKey = nessusglpi_vuln_severity_key($row);
    $rows[] = [
        'data'   => $row,
        'host'   => $hostRow,
        'sevKey' => $sevKey,
        'ticket' => nessusglpi_vuln_existing_ticket($row),
    ];
}
$bulkFormId = 'nessusglpi-scan-bulk-ticket-form';

echo '<div class="card card-body nessus-vuln-page" data-nessus-vuln-page data-nessus-bulk-form="' . Html::cleanInputText($bulkFormId) . '">';

echo '<div class="nessus-vuln-page__back">';
echo '<a class="nessus-btn-back" href="scan.php">' . nessusglpi_vuln_icon('arrow-left') . '<span>' . Html::cleanInputText(__('Back')) . '</span></a>';
echo '</div>';

echo '<div class="nessus-vuln-page__hero">';
echo '<div class="nessus-vuln-page__title-group">';
echo '<h2 class="nessus-vuln-page__title">🛡️ ' . Html::cleanInputText(__('Scan vulnerabilities', 'nessusglpi')) . '</h2>';
echo '<span class="nessus-vuln-page__scan-pill">' . Html::cleanInputText((string) ($scan->fields['name'] ?? '')) . ' · #' . (int) $scan->fields['id'] . '</span>';
echo '</div>';
echo '</div>';

if ($totalVulns === 0) {
    echo '<div class="nessus-vuln-empty">';
    echo nessusglpi_vuln_icon('inbox');
    echo '<h3>' . Html::cleanInputText(__('No vulnerabilities imported for this scan yet', 'nessusglpi')) . '</h3>';
    echo '<p>' . Html::cleanInputText(__('Queue a synchronization from the scans list to import findings.', 'nessusglpi')) . '</p>';
    echo '</div>';
    echo '</div>';
    Html::footer();
    return;
}

echo '<div class="nessus-sev-dashboard">';
foreach (['critical', 'high', 'medium', 'low', 'info'] as $key) {
    echo '<button type="button" class="nessus-sev-card nessus-sev-card--' . $key . '" data-nessus-sev-card="' . $key . '" aria-pressed="false" title="' . Html::cleanInputText(sprintf(__('Filter by %s', 'nessusglpi'), nessusglpi_vuln_severity_label($key))) . '">';
    echo '<span class="nessus-sev-card__icon">' . nessusglpi_vuln_severity_icon($key) . '</span>';
    echo '<span class="nessus-sev-card__count">' . (int) $counts[$key] . '</span>';
    echo '<span class="nessus-sev-card__label">' . Html::cleanInputText(nessusglpi_vuln_severity_label($key)) . '</span>';
    echo '</button>';
}
echo '</div>';

echo '<div class="nessus-sev-distribution">';
foreach (['critical', 'high', 'medium', 'low', 'info'] as $key) {
    $count = (int) $counts[$key];
    if ($count <= 0) continue;
    $width = ($count / $totalVulns) * 100;
    $widthStr = rtrim(rtrim(number_format(max($width, 4), 2, '.', ''), '0'), '.');
    echo '<div class="nessus-sev-distribution__segment nessus-sev-distribution__segment--' . $key . '" style="flex: ' . $widthStr . ' 0 0; min-width: 30px;" title="' . Html::cleanInputText(nessusglpi_vuln_severity_label($key) . ': ' . $count) . '">' . $count . '</div>';
}
echo '</div>';

echo '<div class="nessus-vuln-page__total">' . sprintf(Html::cleanInputText(__('Total current vulnerabilities: %d', 'nessusglpi')), $totalVulns) . '</div>';

echo '<form id="' . Html::cleanInputText($bulkFormId) . '" method="post" action="vulnerability.ticket.php">';
echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
echo '</form>';

echo '<div class="nessus-vuln-page__toolbar">';
echo '<label class="nessus-vuln-page__select-all">';
echo '<input type="checkbox" data-nessus-vuln-master-check aria-label="' . Html::cleanInputText(__('Select all filtered vulnerabilities', 'nessusglpi')) . '">';
echo '<span>' . Html::cleanInputText(__('Select filtered', 'nessusglpi')) . '</span>';
echo '</label>';
echo '<label class="nessus-vuln-page__search">';
echo '<input type="search" data-nessus-vuln-search autocomplete="off" spellcheck="false" placeholder="' . Html::cleanInputText(__('Search by name, host, CVE…', 'nessusglpi')) . '">';
echo '</label>';

echo '<select class="nessus-vuln-page__filter" data-nessus-vuln-ticket-filter aria-label="' . Html::cleanInputText(__('Filter by ticket status', 'nessusglpi')) . '">';
echo '<option value="all">' . Html::cleanInputText(__('All', 'nessusglpi')) . '</option>';
echo '<option value="none">🎫 ' . Html::cleanInputText(__('Without ticket', 'nessusglpi')) . '</option>';
echo '<option value="has">✅ ' . Html::cleanInputText(__('With ticket', 'nessusglpi')) . '</option>';
echo '</select>';

// Host filter (server-side): lists only hosts with current findings; selecting
// one reloads the page scoped to that host (list + dashboard recompute).
echo '<form method="get" class="nessus-vuln-page__host-form">';
echo Html::hidden('scan_id', ['value' => $scanId]);
echo Html::hidden('_limit', ['value' => $perPage]);
echo '<select name="host_id" class="nessus-vuln-page__filter" onchange="this.form.submit()" aria-label="' . Html::cleanInputText(__('Filter by host', 'nessusglpi')) . '">';
echo '<option value="0">🖥️ ' . Html::cleanInputText(__('All hosts', 'nessusglpi')) . '</option>';
foreach ($hostLabels as $hid => $label) {
    $sel = ($hostFilter === (int) $hid) ? ' selected' : '';
    echo '<option value="' . (int) $hid . '"' . $sel . '>'
        . Html::cleanInputText($label . ' (' . (int) $hostCounts[$hid] . ')')
        . '</option>';
}
echo '</select>';
echo '</form>';

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
    $ticket = $r['ticket'];
    $hostMeta = nessusglpi_vuln_host_link($row, $hostRow);
    $vulnId = (int) $row['id'];
    $vulnName = (string) ($row['plugin_name'] ?? '');
    $cve = trim((string) ($row['cve'] ?? ''));
    $hasTicket = is_array($ticket);

    $haystack = strtolower(trim($vulnName . ' ' . $hostMeta['label'] . ' ' . $cve));

    echo '<article class="nessus-vuln-row" data-nessus-vuln-row'
        . ' data-severity="' . Html::cleanInputText($sevKey) . '"'
        . ' data-ticket="' . ($hasTicket ? '1' : '0') . '"'
        . ' data-haystack="' . Html::cleanInputText($haystack) . '"'
        . ' data-selected="false">';

    echo '<label class="nessus-vuln-row__check">';
    if ($hasTicket) {
        echo '<span class="nessus-vuln-row__check--placeholder"></span>';
    } else {
        echo '<input type="checkbox" data-nessus-vuln-row-check name="ids[]" value="' . $vulnId . '" form="' . Html::cleanInputText($bulkFormId) . '">';
    }
    echo '</label>';

    echo '<span class="nessus-sev-chip nessus-sev-chip--' . Html::cleanInputText($sevKey) . '">'
        . nessusglpi_vuln_severity_icon($sevKey) . ' '
        . Html::cleanInputText(nessusglpi_vuln_severity_label($sevKey))
        . '</span>';

    echo '<div class="nessus-vuln-row__body">';
    echo '<h3 class="nessus-vuln-row__title"><a href="vulnerability.form.php?id=' . $vulnId . '">'
        . Html::cleanInputText($vulnName !== '' ? $vulnName : __('Unnamed', 'nessusglpi')) . '</a></h3>';
    echo '<div class="nessus-vuln-row__meta">';
    echo '<span class="nessus-vuln-row__meta-item">🖥️ ';
    if ($hostMeta['href']) {
        echo '<a href="' . Html::cleanInputText($hostMeta['href']) . '">' . Html::cleanInputText($hostMeta['label']) . '</a>';
    } else {
        echo Html::cleanInputText($hostMeta['label']);
    }
    echo '</span>';
    if ($cve !== '') {
        echo '<span class="nessus-vuln-row__meta-item">🔗 ' . Html::cleanInputText($cve) . '</span>';
    }
    if ($hasTicket) {
        $ticketLabel = '#' . (int) $ticket['id'];
        echo '<a class="nessus-vuln-row__ticket" href="' . Html::cleanInputText($ticket['link']) . '" title="' . Html::cleanInputText($ticket['name'] ?? '') . '">'
            . '🎫 ' . Html::cleanInputText($ticketLabel) . '</a>';
    }
    echo '</div>';
    echo '</div>';

    echo '<div class="nessus-vuln-row__actions">';
    echo '<a class="nessus-vuln-btn" href="vulnerability.form.php?id=' . $vulnId . '">' . nessusglpi_vuln_icon('eye') . '<span>' . Html::cleanInputText(__('Details', 'nessusglpi')) . '</span></a>';

    if ($hasTicket) {
        echo '<form method="post" action="vulnerability.ticket.php" data-nessus-vuln-ticket-form style="display:inline-flex;"'
            . ' data-confirm-title="' . Html::cleanInputText(__('Open a new ticket?', 'nessusglpi')) . '"'
            . ' data-confirm-message="' . Html::cleanInputText(__('A new ticket will be created even though this vulnerability already has one linked.', 'nessusglpi')) . '"'
            . ' data-confirm-label="' . Html::cleanInputText(__('Create', 'nessusglpi')) . '"'
            . ' data-cancel-label="' . Html::cleanInputText(__('Cancel')) . '">';
        echo Html::hidden('id', ['value' => $vulnId]);
        echo Html::hidden('force_new', ['value' => 1]);
        echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
        echo '<button type="submit" name="force_new_ticket" value="1" class="nessus-vuln-btn">' . nessusglpi_vuln_icon('plus') . '<span>' . Html::cleanInputText(__('New ticket', 'nessusglpi')) . '</span></button>';
        echo '</form>';
    } else {
        echo '<form method="post" action="vulnerability.ticket.php" data-nessus-vuln-ticket-form style="display:inline-flex;"'
            . ' data-confirm-title="' . Html::cleanInputText(__('Create ticket?', 'nessusglpi')) . '"'
            . ' data-confirm-message="' . Html::cleanInputText(sprintf(__('A ticket will be created for "%s".', 'nessusglpi'), $vulnName !== '' ? $vulnName : ('#' . $vulnId))) . '"'
            . ' data-confirm-label="' . Html::cleanInputText(__('Create', 'nessusglpi')) . '"'
            . ' data-cancel-label="' . Html::cleanInputText(__('Cancel')) . '">';
        echo Html::hidden('id', ['value' => $vulnId]);
        echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
        echo '<button type="submit" name="create_ticket" value="1" class="nessus-vuln-btn nessus-vuln-btn--primary">' . nessusglpi_vuln_icon('ticket') . '<span>' . Html::cleanInputText(__('Create ticket', 'nessusglpi')) . '</span></button>';
        echo '</form>';
    }

    echo '</div>';
    echo '</article>';
}

echo '</div>';

echo '<div class="nessus-vuln-empty" data-nessus-vuln-empty hidden>';
echo nessusglpi_vuln_icon('search');
echo '<h3>' . Html::cleanInputText(__('No vulnerabilities match your filters', 'nessusglpi')) . '</h3>';
echo '<p>' . Html::cleanInputText(__('Try a different search or clear the severity filters.', 'nessusglpi')) . '</p>';
echo '</div>';

// Pagination bar
if ($totalVulns > $perPage || $start > 0) {
    $totalPages  = max(1, (int) ceil($totalVulns / $perPage));
    $currentPage = (int) floor($start / $perPage) + 1;
    $baseUrl     = Html::cleanInputText($_SERVER['PHP_SELF'] . '?scan_id=' . $scanId . '&_limit=' . $perPage . '&host_id=' . $hostFilter);

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
    echo Html::hidden('scan_id', ['value' => $scanId]);
    echo Html::hidden('host_id', ['value' => $hostFilter]);
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

echo '<div class="nessus-selection-bar" data-nessus-vuln-selection-bar>';
echo '<span class="nessus-selection-bar__count"><strong data-nessus-vuln-selection-count>0</strong> '
    . Html::cleanInputText(__('selected', 'nessusglpi')) . '</span>';
echo '<span class="nessus-selection-bar__divider"></span>';
echo '<button type="button" class="is-primary" data-nessus-vuln-bulk'
    . ' data-submit-mode="create_selected_tickets"'
    . ' data-empty-text="' . Html::cleanInputText(__('Select at least one vulnerability.', 'nessusglpi')) . '"'
    . ' data-confirm-title="' . Html::cleanInputText(__('Create individual tickets?', 'nessusglpi')) . '"'
    . ' data-confirm-message="' . Html::cleanInputText(__('A separate ticket will be created for each of the %d selected vulnerabilities.', 'nessusglpi')) . '"'
    . ' data-confirm-label="' . Html::cleanInputText(__('Create tickets', 'nessusglpi')) . '"'
    . ' data-cancel-label="' . Html::cleanInputText(__('Cancel')) . '">'
    . '🎫 <span>' . Html::cleanInputText(__('Create selected', 'nessusglpi')) . '</span>'
    . '</button>';
echo '<button type="button" data-nessus-vuln-bulk'
    . ' data-submit-mode="create_grouped_tickets"'
    . ' data-empty-text="' . Html::cleanInputText(__('Select at least one vulnerability.', 'nessusglpi')) . '"'
    . ' data-confirm-title="' . Html::cleanInputText(__('Create grouped tickets?', 'nessusglpi')) . '"'
    . ' data-confirm-message="' . Html::cleanInputText(__('Selected vulnerabilities will produce one parent ticket per plugin/CVE group, with a child ticket per affected host (%d vulnerabilities total).', 'nessusglpi')) . '"'
    . ' data-confirm-label="' . Html::cleanInputText(__('Group & create', 'nessusglpi')) . '"'
    . ' data-cancel-label="' . Html::cleanInputText(__('Cancel')) . '">'
    . '🛡️ <span>' . Html::cleanInputText(__('Group & create', 'nessusglpi')) . '</span>'
    . '</button>';
echo '</div>';

echo '</div>';

echo '<script src="' . Html::cleanInputText($assetsBase . '/js/vulnerabilities.js?v=' . $jsVersion) . '" defer></script>';

Html::footer();
