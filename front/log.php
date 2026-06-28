<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\AuditLog;
use GlpiPlugin\Nessusglpi\Config;
use GlpiPlugin\Nessusglpi\Scan;

include('../../../inc/includes.php');

Session::checkRight(Config::$rightname, READ);

global $DB, $CFG_GLPI;

$assetsBase   = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
$assetVersion = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';

$rows = [];
foreach ($DB->request([
    'FROM'  => AuditLog::getTable(),
    'ORDER' => ['id DESC'],
    'LIMIT' => 200,
]) as $row) {
    $rows[] = $row;
}

$total    = count($rows);
$errors   = 0;
$warnings = 0;
foreach ($rows as $row) {
    $level = (string) ($row['level'] ?? '');
    if ($level === AuditLog::LEVEL_ERROR) {
        $errors++;
    } elseif ($level === AuditLog::LEVEL_WARNING) {
        $warnings++;
    }
}

$levelMeta = static function (string $level): array {
    return match ($level) {
        AuditLog::LEVEL_ERROR   => ['label' => __('Error'), 'bg' => '#fef2f2', 'fg' => '#b91c1c', 'border' => '#fecaca'],
        AuditLog::LEVEL_WARNING => ['label' => __('Warning'), 'bg' => '#fff7ed', 'fg' => '#9a3412', 'border' => '#fed7aa'],
        default                 => ['label' => __('Info'), 'bg' => '#eff6ff', 'fg' => '#1e40af', 'border' => '#bfdbfe'],
    };
};

Html::header(__('Activity log', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

echo '<link rel="stylesheet" href="' . Html::cleanInputText($assetsBase . '/css/scan-list.css?v=' . $assetVersion) . '">';

echo '<div class="card card-body nessus-list-page" data-nessus-list-page>';

echo '<div class="nessus-list-page__hero">';
echo '<div class="nessus-list-page__title-group">';
echo '<h2 class="nessus-list-page__title">' . Html::cleanInputText(__('Activity log', 'nessusglpi')) . '</h2>';
echo '<div class="nessus-list-page__stats">';
echo '<span class="nessus-stat-pill"><span class="nessus-stat-pill__dot"></span>'
    . sprintf(Html::cleanInputText(_n('%d entry', '%d entries', $total, 'nessusglpi')), $total)
    . '</span>';
if ($warnings > 0) {
    echo '<span class="nessus-stat-pill nessus-stat-pill--warn"><span class="nessus-stat-pill__dot"></span>'
        . sprintf(Html::cleanInputText(_n('%d warning', '%d warnings', $warnings, 'nessusglpi')), $warnings)
        . '</span>';
}
if ($errors > 0) {
    echo '<span class="nessus-stat-pill nessus-stat-pill--warn"><span class="nessus-stat-pill__dot"></span>'
        . sprintf(Html::cleanInputText(_n('%d error', '%d errors', $errors, 'nessusglpi')), $errors)
        . '</span>';
}
echo '</div>';
echo '</div>';

echo '<div class="nessus-list-page__actions">';
echo '<a class="nessus-btn-outline" href="scan.php"><span>'
    . Html::cleanInputText(__('Back to scans', 'nessusglpi')) . '</span></a>';
echo '</div>';
echo '</div>';

if ($total === 0) {
    echo '<p style="margin-top:16px; color:#6b7280;">'
        . Html::cleanInputText(__('No activity has been recorded yet.', 'nessusglpi')) . '</p>';
} else {
    echo '<div style="margin-top:18px; overflow-x:auto;">';
    echo '<table style="width:100%; border-collapse:collapse; font-size:13px;">';
    echo '<thead><tr>';
    foreach ([
        __('Date'),
        __('Level', 'nessusglpi'),
        __('Context', 'nessusglpi'),
        __('Message'),
    ] as $heading) {
        echo '<th style="text-align:left; padding:8px 12px; border-bottom:1px solid #dee2e6; color:#6c757d; font-size:11px; text-transform:uppercase; letter-spacing:0.03em; white-space:nowrap;">'
            . Html::cleanInputText($heading) . '</th>';
    }
    echo '</tr></thead><tbody>';

    foreach ($rows as $row) {
        $level   = (string) ($row['level'] ?? AuditLog::LEVEL_INFO);
        $meta    = $levelMeta($level);
        $date    = (string) ($row['date_creation'] ?? '');
        $relative = Scan::relativeDate($date);

        echo '<tr>';
        echo '<td style="padding:8px 12px; border-bottom:1px solid #f1f5f9; white-space:nowrap; color:#475569;" title="'
            . Html::cleanInputText($date) . '">'
            . Html::cleanInputText($relative !== '' ? $relative : $date) . '</td>';
        echo '<td style="padding:8px 12px; border-bottom:1px solid #f1f5f9;">'
            . '<span style="display:inline-block; padding:2px 10px; border-radius:999px; font-size:11px; font-weight:700;'
            . ' background:' . $meta['bg'] . '; color:' . $meta['fg'] . '; border:1px solid ' . $meta['border'] . ';">'
            . Html::cleanInputText($meta['label']) . '</span></td>';
        echo '<td style="padding:8px 12px; border-bottom:1px solid #f1f5f9; color:#6c757d; font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px; white-space:nowrap;">'
            . Html::cleanInputText((string) ($row['context'] ?? '')) . '</td>';
        echo '<td style="padding:8px 12px; border-bottom:1px solid #f1f5f9; color:#0f172a;">'
            . Html::cleanInputText((string) ($row['message'] ?? '')) . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
    echo '</div>';
}

echo '</div>';

Html::footer();
