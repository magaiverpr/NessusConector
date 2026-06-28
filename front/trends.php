<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Trends;
use GlpiPlugin\Nessusglpi\Vulnerability;

include('../../../inc/includes.php');

global $CFG_GLPI;

Session::checkRight(Vulnerability::$rightname, READ);

Html::header(
    __('Vulnerability trends', 'nessusglpi'),
    $_SERVER['PHP_SELF'],
    'plugins',
    'GlpiPlugin\\Nessusglpi\\Scan'
);

$rootDoc    = (string) ($CFG_GLPI['root_doc'] ?? '');
$assetsBase = $rootDoc . '/plugins/nessusglpi';
$assetDir   = __DIR__ . '/../public';
$cssVersion = (defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1')
    . '-' . (@filemtime($assetDir . '/css/trends.css') ?: '0');

echo '<link rel="stylesheet" href="' . Html::cleanInputText($assetsBase . '/css/trends.css?v=' . $cssVersion) . '">';

$h = static fn ($v): string => Html::cleanInputText((string) $v);

$windows = Trends::windows();
$days    = (int) ($_GET['days'] ?? 90);
if (!isset($windows[$days])) {
    $days = 90;
}

$cmp      = Trends::comparison($days);
$timeline = Trends::timeline($days);
$runs     = Trends::scanRuns(15);

$baseUrl = $assetsBase . '/front/trends.php';

// Delta -> badge. Subir vulnerabilidades = pior (vermelho); descer = melhor (verde).
$deltaBadge = static function (int $delta) use ($h): string {
    if ($delta > 0) {
        return '<span class="ng-delta ng-delta--up"><span class="ti ti-trending-up"></span>+' . $h($delta) . '</span>';
    }
    if ($delta < 0) {
        return '<span class="ng-delta ng-delta--down"><span class="ti ti-trending-down"></span>' . $h($delta) . '</span>';
    }
    return '<span class="ng-delta ng-delta--flat"><span class="ti ti-minus"></span>0</span>';
};

$sevMeta = [
    'Critical' => ['Críticas', 'critical'],
    'High'     => ['Altas', 'high'],
    'Medium'   => ['Médias', 'medium'],
    'Low'      => ['Baixas', 'low'],
];

echo '<div class="card card-body ng-trends">';

// ─── HERO ───
echo '<div class="ng-trends__hero">';
echo '<div class="ng-trends__brand">';
echo '<span class="ng-trends__logo"><span class="ti ti-chart-arrows-vertical"></span></span>';
echo '<div>';
echo '<span class="ng-trends__eyebrow">Nessus · Analytics</span>';
echo '<h2>' . $h(__('Tendência de Vulnerabilidades', 'nessusglpi')) . '</h2>';
echo '<p>' . sprintf(
    $h(__('%1$s vulnerabilidades abertas · comparando com %2$s atrás', 'nessusglpi')),
    '<strong>' . $h($cmp['now']) . '</strong>',
    '<strong>' . $h($windows[$days]) . '</strong>'
) . '</p>';
echo '</div></div>';

echo '<div class="ng-trends__windows">';
foreach ($windows as $d => $label) {
    $active = $d === $days ? ' is-active' : '';
    echo '<a class="ng-win' . $active . '" href="' . $h($baseUrl . '?days=' . $d) . '">' . $h($label) . '</a>';
}
echo '</div>';
echo '</div>';

// ─── COMPARATIVO PRINCIPAL ───
echo '<div class="ng-panel">';
echo '<div class="ng-panel__head"><span class="ti ti-arrows-diff"></span><div><h3>'
    . $h(__('Backlog: agora vs.', 'nessusglpi')) . ' ' . $h($windows[$days]) . ' ' . $h(__('atrás', 'nessusglpi'))
    . '</h3><p>' . $h(__('Total de vulnerabilidades abertas no período', 'nessusglpi')) . '</p></div></div>';
echo '<div class="ng-panel__body">';

echo '<div class="ng-compare">';
echo '<div class="ng-compare__cell"><span class="ng-compare__label">' . $h(__('Agora', 'nessusglpi')) . '</span>'
    . '<span class="ng-compare__big">' . $h($cmp['now']) . '</span>'
    . '<span class="ng-compare__sub">' . $h(__('vulnerabilidades abertas', 'nessusglpi')) . '</span></div>';

echo '<div class="ng-compare__cell"><span class="ng-compare__label">' . $h($windows[$days]) . ' ' . $h(__('atrás', 'nessusglpi')) . '</span>'
    . '<span class="ng-compare__big">' . ($cmp['covers_window'] ? $h($cmp['then']) : '—') . '</span>'
    . '<span class="ng-compare__sub">' . $h(__('backlog estimado', 'nessusglpi')) . '</span></div>';

echo '<div class="ng-compare__cell"><span class="ng-compare__label">' . $h(__('Variação', 'nessusglpi')) . '</span>';
if ($cmp['covers_window']) {
    echo $deltaBadge((int) $cmp['delta']);
    $word = $cmp['delta'] > 0 ? __('subiu', 'nessusglpi') : ($cmp['delta'] < 0 ? __('desceu', 'nessusglpi') : __('estável', 'nessusglpi'));
    echo '<span class="ng-compare__sub">' . $h($word) . '</span>';
} else {
    echo '<span class="ng-compare__big">—</span><span class="ng-compare__sub">' . $h(__('sem baseline', 'nessusglpi')) . '</span>';
}
echo '</div>';
echo '</div>';

// fluxo abertas/resolvidas no período
echo '<div class="ng-flow">';
echo '<span class="ng-flow__item"><span class="ng-flow__dot ng-flow__dot--open"></span>'
    . sprintf($h(__('%s novas no período', 'nessusglpi')), '<strong>' . $h($cmp['opened']) . '</strong>') . '</span>';
echo '<span class="ng-flow__item"><span class="ng-flow__dot ng-flow__dot--res"></span>'
    . sprintf($h(__('%s resolvidas no período', 'nessusglpi')), '<strong>' . $h($cmp['resolved']) . '</strong>') . '</span>';
echo '</div>';

if (!$cmp['covers_window']) {
    $since = $cmp['data_since'] ? date('d/m/Y', strtotime((string) $cmp['data_since'])) : '—';
    echo '<div class="ng-note"><span class="ti ti-info-circle"></span><div>'
        . sprintf($h(__('O histórico começa em %s, anterior a esta janela. A comparação ficará completa conforme novos scans acumulam dados.', 'nessusglpi')), $since)
        . '</div></div>';
}

echo '</div></div>';

// ─── SEVERIDADE ───
echo '<div class="ng-panel">';
echo '<div class="ng-panel__head"><span class="ti ti-alert-octagon"></span><div><h3>'
    . $h(__('Por severidade', 'nessusglpi')) . '</h3><p>' . $h(__('Abertas hoje e variação no período', 'nessusglpi')) . '</p></div></div>';
echo '<div class="ng-panel__body"><div class="ng-sev-grid">';
foreach ($sevMeta as $key => [$label, $mod]) {
    $s     = $cmp['by_severity'][$key] ?? ['now' => 0, 'delta' => 0];
    $delta = (int) $s['delta'];
    if (!$cmp['covers_window']) {
        $dHtml = '<span class="ng-sev-card__delta ng-sev-card__delta--flat"><span class="ti ti-clock"></span>' . $h(__('novo', 'nessusglpi')) . '</span>';
    } elseif ($delta > 0) {
        $dHtml = '<span class="ng-sev-card__delta ng-sev-card__delta--up"><span class="ti ti-trending-up"></span>+' . $h($delta) . '</span>';
    } elseif ($delta < 0) {
        $dHtml = '<span class="ng-sev-card__delta ng-sev-card__delta--down"><span class="ti ti-trending-down"></span>' . $h($delta) . '</span>';
    } else {
        $dHtml = '<span class="ng-sev-card__delta ng-sev-card__delta--flat"><span class="ti ti-minus"></span>' . $h(__('estável', 'nessusglpi')) . '</span>';
    }
    echo '<div class="ng-sev-card ng-sev-card--' . $mod . '">'
        . '<span class="ng-sev-card__name">' . $h($label) . '</span>'
        . '<span class="ng-sev-card__num">' . $h((int) $s['now']) . '</span>'
        . $dHtml . '</div>';
}
echo '</div></div></div>';

// ─── GRÁFICO MENSAL (abertas vs resolvidas) ───
if ($timeline !== []) {
    $maxBar = 1;
    foreach ($timeline as $b) {
        $maxBar = max($maxBar, $b['opened'], $b['resolved']);
    }
    echo '<div class="ng-panel">';
    echo '<div class="ng-panel__head"><span class="ti ti-chart-bar"></span><div><h3>'
        . $h(__('Novas vs. resolvidas por mês', 'nessusglpi')) . '</h3><p>' . $h(__('Evolução no período selecionado', 'nessusglpi')) . '</p></div></div>';
    echo '<div class="ng-panel__body">';
    echo '<div class="ng-chart">';
    foreach ($timeline as $b) {
        $ho = (int) round($b['opened'] / $maxBar * 100);
        $hr = (int) round($b['resolved'] / $maxBar * 100);
        echo '<div class="ng-chart__col">';
        echo '<div class="ng-chart__bars">';
        echo '<div class="ng-chart__bar ng-chart__bar--open" style="height:' . $ho . '%" title="' . $h(__('Novas', 'nessusglpi')) . ': ' . $h($b['opened']) . '"></div>';
        echo '<div class="ng-chart__bar ng-chart__bar--res" style="height:' . $hr . '%" title="' . $h(__('Resolvidas', 'nessusglpi')) . ': ' . $h($b['resolved']) . '"></div>';
        echo '</div>';
        echo '<span class="ng-chart__val">+' . $h($b['opened']) . ' / -' . $h($b['resolved']) . '</span>';
        echo '<span class="ng-chart__label">' . $h($b['label']) . '</span>';
        echo '</div>';
    }
    echo '</div>';
    echo '<div class="ng-flow" style="border:0;margin-top:.4rem">';
    echo '<span class="ng-flow__item"><span class="ng-flow__dot ng-flow__dot--open"></span>' . $h(__('Novas', 'nessusglpi')) . '</span>';
    echo '<span class="ng-flow__item"><span class="ng-flow__dot ng-flow__dot--res"></span>' . $h(__('Resolvidas', 'nessusglpi')) . '</span>';
    echo '</div>';
    echo '</div></div>';
}

// ─── HISTÓRICO DE EXECUÇÕES (scan atual vs antigo) ───
echo '<div class="ng-panel">';
echo '<div class="ng-panel__head"><span class="ti ti-history"></span><div><h3>'
    . $h(__('Execuções de scan', 'nessusglpi')) . '</h3><p>' . $h(__('Cada execução vs. a anterior do mesmo scan', 'nessusglpi')) . '</p></div></div>';
echo '<div style="overflow-x:auto">';
echo '<table class="ng-runs"><thead><tr>'
    . '<th>' . $h(__('Scan', 'nessusglpi')) . '</th>'
    . '<th>' . $h(__('Data', 'nessusglpi')) . '</th>'
    . '<th style="text-align:right">' . $h(__('Hosts', 'nessusglpi')) . '</th>'
    . '<th style="text-align:right">' . $h(__('Vulns', 'nessusglpi')) . '</th>'
    . '<th style="text-align:right">' . $h(__('vs. anterior', 'nessusglpi')) . '</th>'
    . '</tr></thead><tbody>';
foreach ($runs as $r) {
    if ($r['delta'] === null) {
        $pill = '<span class="ng-pill ng-pill--new">' . $h(__('1ª execução', 'nessusglpi')) . '</span>';
    } elseif ($r['delta'] > 0) {
        $pill = '<span class="ng-pill ng-pill--up"><span class="ti ti-arrow-up-right"></span>+' . $h($r['delta']) . '</span>';
    } elseif ($r['delta'] < 0) {
        $pill = '<span class="ng-pill ng-pill--down"><span class="ti ti-arrow-down-right"></span>' . $h($r['delta']) . '</span>';
    } else {
        $pill = '<span class="ng-pill ng-pill--flat">0</span>';
    }
    echo '<tr>'
        . '<td class="ng-runs__name">' . $h($r['scan_name']) . '</td>'
        . '<td>' . ($r['started_at'] ? $h(date('d/m/Y H:i', strtotime($r['started_at']))) : '—') . '</td>'
        . '<td style="text-align:right">' . $h($r['hosts']) . '</td>'
        . '<td style="text-align:right" class="ng-runs__num">' . $h($r['vulns']) . '</td>'
        . '<td style="text-align:right">' . $pill . '</td>'
        . '</tr>';
}
if ($runs === []) {
    echo '<tr><td colspan="5" style="text-align:center;padding:1.5rem;color:#6c757d">' . $h(__('Nenhuma execução registrada.', 'nessusglpi')) . '</td></tr>';
}
echo '</tbody></table></div></div>';

echo '</div>';

Html::footer();
