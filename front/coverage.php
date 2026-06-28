<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Coverage;
use GlpiPlugin\Nessusglpi\Host;

include('../../../inc/includes.php');

global $CFG_GLPI;

Session::checkRight(Host::$rightname, READ);

Html::header(
    __('Nessus coverage', 'nessusglpi'),
    $_SERVER['PHP_SELF'],
    'plugins',
    'GlpiPlugin\\Nessusglpi\\Scan'
);

$rootDoc      = (string) ($CFG_GLPI['root_doc'] ?? '');
$assetsBase   = $rootDoc . '/plugins/nessusglpi';
$assetVersion = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';
$assetDir     = __DIR__ . '/../public';
$cssVersion   = $assetVersion . '-' . (@filemtime($assetDir . '/css/scan-list.css') ?: '0');

echo '<link rel="stylesheet" href="' . Html::cleanInputText($assetsBase . '/css/scan-list.css?v=' . $cssVersion) . '">';

$stats     = Coverage::stats();
$uncovered = Coverage::uncovered();

$coveragePct = $stats['vms_total'] > 0
    ? (int) round(($stats['covered'] / $stats['vms_total']) * 100)
    : 0;

$h = static fn ($value): string => Html::cleanInputText((string) $value);

$categoryChip = static function (string $category) use ($h): string {
    if ($category === 'winserver') {
        return '<span class="nessus-os-chip nessus-os-chip--winserver"><i class="ti ti-brand-windows"></i>'
            . $h(__('Windows Server', 'nessusglpi')) . '</span>';
    }

    return '<span class="nessus-os-chip nessus-os-chip--linux"><i class="ti ti-brand-tux"></i>'
        . $h(__('Linux', 'nessusglpi')) . '</span>';
};

echo '<div class="card card-body nessus-list-page">';

echo '<div class="nessus-list-page__hero">';
echo '<div class="nessus-list-page__title-group">';
echo '<h2 class="nessus-list-page__title">' . $h(__('Virtual machines without Nessus', 'nessusglpi')) . '</h2>';
echo '<div class="nessus-list-page__stats">';
echo '<span class="nessus-stat-pill nessus-stat-pill--warn"><span class="nessus-stat-pill__dot"></span>'
    . sprintf($h(_n('%d uncovered VM', '%d uncovered VMs', $stats['uncovered'], 'nessusglpi')), $stats['uncovered'])
    . '</span>';
echo '<span class="nessus-stat-pill"><span class="nessus-stat-pill__dot"></span>'
    . sprintf($h(__('%d Linux', 'nessusglpi')), $stats['uncovered_linux']) . '</span>';
echo '<span class="nessus-stat-pill"><span class="nessus-stat-pill__dot"></span>'
    . sprintf($h(__('%d Windows Server', 'nessusglpi')), $stats['uncovered_winserver']) . '</span>';
echo '<span class="nessus-stat-pill nessus-stat-pill--muted">'
    . sprintf($h(__('%1$d of %2$d covered (%3$d%%)', 'nessusglpi')), $stats['covered'], $stats['vms_total'], $coveragePct)
    . '</span>';
echo '</div>';
echo '</div>';

echo '<div class="nessus-list-page__actions">';
echo '<a class="nessus-btn-outline" href="scan.php"><i class="ti ti-list-details"></i><span>' . $h(__('Scans', 'nessusglpi')) . '</span></a>';
echo '<a class="nessus-btn-outline" href="scan.browser.php?source=nessus"><i class="ti ti-search"></i><span>' . $h(__('Browse scans', 'nessusglpi')) . '</span></a>';
echo '</div>';
echo '</div>';

echo '<p class="nessus-coverage-note">'
    . $h(__('Only virtual machines running Linux or Windows Server are listed. A machine is considered covered when it is matched to an imported Nessus host.', 'nessusglpi'))
    . '</p>';

if ($uncovered === []) {
    echo '<div class="nessus-coverage-empty">';
    echo '<i class="ti ti-shield-check"></i>';
    echo '<strong>' . $h(__('No uncovered virtual machines found.', 'nessusglpi')) . '</strong>';
    echo '<span>' . $h(__('Every Linux / Windows Server VM in scope is matched to a Nessus host.', 'nessusglpi')) . '</span>';
    echo '</div>';
} else {
    echo '<div class="table-responsive">';
    echo '<table class="table table-hover card-table nessus-coverage-table">';
    echo '<thead><tr>';
    echo '<th>' . $h(__('Computer')) . '</th>';
    echo '<th>' . $h(__('OS family', 'nessusglpi')) . '</th>';
    echo '<th>' . $h(__('Operating system', 'nessusglpi')) . '</th>';
    echo '<th>' . $h(__('Type')) . '</th>';
    echo '<th>' . $h(__('Model')) . '</th>';
    echo '<th>' . $h(__('Serial number')) . '</th>';
    echo '<th>' . $h(__('Entity')) . '</th>';
    echo '</tr></thead>';
    echo '<tbody>';

    foreach ($uncovered as $row) {
        $computerUrl = $rootDoc . '/front/computer.form.php?id=' . (int) $row['id'];
        $name = $row['name'] !== '' ? $row['name'] : ('#' . (int) $row['id']);
        $entityName = $row['entities_id'] > 0
            ? Dropdown::getDropdownName('glpi_entities', $row['entities_id'])
            : '-';

        echo '<tr>';
        echo '<td><a href="' . $h($computerUrl) . '">' . $h($name) . '</a></td>';
        echo '<td>' . $categoryChip((string) $row['category']) . '</td>';
        echo '<td>' . $h($row['os_name'] !== '' ? $row['os_name'] : '-') . '</td>';
        echo '<td>' . $h($row['ctype'] !== '' ? $row['ctype'] : '-') . '</td>';
        echo '<td>' . $h($row['cmodel'] !== '' ? $row['cmodel'] : '-') . '</td>';
        echo '<td>' . $h($row['serial'] !== '' ? $row['serial'] : '-') . '</td>';
        echo '<td>' . $h($entityName) . '</td>';
        echo '</tr>';
    }

    echo '</tbody>';
    echo '</table>';
    echo '</div>';
}

echo '</div>';

Html::footer();
