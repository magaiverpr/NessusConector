<?php

declare(strict_types=1);

global $DB, $CFG_GLPI;

include('../../../inc/includes.php');

use GlpiPlugin\Nessusglpi\Host;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\Vulnerability;
use GlpiPlugin\Nessusglpi\VulnerabilityTicket;

if (!Plugin::isPluginActive('nessusglpi')) {
    Html::displayErrorAndDie('Plugin Nessus não está ativo.');
}

Session::checkRight(Scan::$rightname, READ);

$h = static fn($v): string => htmlspecialchars((string)$v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

$period = (int)($_GET['period'] ?? 30);
if (!in_array($period, [7, 30, 90], true)) {
    $period = 30;
}
$trendDays   = $period;
$periodLabel = date('d/m/Y', strtotime("-{$period} days")) . ' – ' . date('d/m/Y');
$genAt       = date('d/m/Y \à\s H:i');

// ── Severity totals (current vulns) ────────────────────────────────────────
$sevTotals = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
$sevLabels = ['critical' => 'Crítica', 'high' => 'Alta', 'medium' => 'Média', 'low' => 'Baixa', 'info' => 'Info'];
$sevColors = [
    'critical' => ['bg' => '#8f233f', 'fg' => '#fff'],
    'high'     => ['bg' => '#b91c1c', 'fg' => '#fff'],
    'medium'   => ['bg' => '#d97706', 'fg' => '#fff'],
    'low'      => ['bg' => '#854d0e', 'fg' => '#fff'],
    'info'     => ['bg' => '#0a6fd0', 'fg' => '#fff'],
];

$keyMap = [
    'critical' => 'critical', 'critica' => 'critical', 'crítica' => 'critical',
    'high'     => 'high',     'alta'    => 'high',
    'medium'   => 'medium',   'media'   => 'medium',   'média' => 'medium',
    'low'      => 'low',      'baixa'   => 'low',
    'info'     => 'info',     'informational' => 'info',
];

// Filtro de período aplicado em todas as queries de vulns
$cutoff   = date('Y-m-d 00:00:00', strtotime("-{$period} days"));
$vWhere   = ['is_current' => 1, 'first_seen_at' => ['>=', $cutoff]];
$vTable   = Vulnerability::getTable();

// Total ativo (sem filtro de período) — para contexto no hero
$totalActive = 0;
foreach ($DB->request(['COUNT' => 'cnt', 'FROM' => $vTable, 'WHERE' => ['is_current' => 1]]) as $r) {
    $totalActive = (int)($r['cnt'] ?? 0);
}

foreach ($DB->request([
    'SELECT'  => ['severity_label', 'severity'],
    'COUNT'   => 'cnt',
    'FROM'    => $vTable,
    'WHERE'   => $vWhere,
    'GROUPBY' => ['severity_label', 'severity'],
]) as $row) {
    $rawKey = strtolower(trim((string)($row['severity_label'] ?? '')));
    $mapped = $keyMap[$rawKey] ?? null;
    if ($mapped === null) {
        $sev = (int)($row['severity'] ?? 0);
        $mapped = match(true) {
            $sev >= 4 => 'critical',
            $sev === 3 => 'high',
            $sev === 2 => 'medium',
            $sev === 1 => 'low',
            default    => 'info',
        };
    }
    $sevTotals[$mapped] += (int)($row['cnt'] ?? 0);
}

$totalVulns    = array_sum($sevTotals);
$criticalCount = $sevTotals['critical'];
$highCount     = $sevTotals['high'];
$critHighCount = $criticalCount + $highCount;

// ── Hosts afetados no período ───────────────────────────────────────────────
$totalHosts  = 0;
$linkedHosts = 0;
// DISTINCT host count via raw SQL
$hResult = $DB->doQuery(
    "SELECT COUNT(DISTINCT plugin_nessusglpi_hosts_id) AS cnt"
    . " FROM `{$vTable}` WHERE is_current=1"
    . " AND first_seen_at >= " . $DB->quoteValue($cutoff)
);
if ($hResult) {
    $totalHosts = (int)(($hResult->fetch_assoc())['cnt'] ?? 0);
}
$hLinkedResult = $DB->doQuery(
    "SELECT COUNT(DISTINCT v.plugin_nessusglpi_hosts_id) AS cnt"
    . " FROM `{$vTable}` v"
    . " JOIN `" . Host::getTable() . "` h ON h.id = v.plugin_nessusglpi_hosts_id"
    . " WHERE v.is_current=1 AND v.first_seen_at >= " . $DB->quoteValue($cutoff)
    . " AND h.items_id > 0"
);
if ($hLinkedResult) {
    $linkedHosts = (int)(($hLinkedResult->fetch_assoc())['cnt'] ?? 0);
}
$unlinkedHosts = $totalHosts - $linkedHosts;

// ── Tickets no período ──────────────────────────────────────────────────────
$withTickets = 0;
foreach ($DB->request(['COUNT' => 'cnt', 'FROM' => VulnerabilityTicket::getTable()]) as $r) {
    $withTickets = (int)($r['cnt'] ?? 0);
}

// ── Scans ───────────────────────────────────────────────────────────────────
$scans = [];
foreach ($DB->request([
    'SELECT' => ['name', 'scan_type', 'last_scan_at', 'last_sync_status', 'is_active'],
    'FROM'   => Scan::getTable(),
    'ORDER'  => ['last_scan_at DESC'],
]) as $row) {
    $scans[] = $row;
}
$lastScanAt = $scans[0]['last_scan_at'] ?? null;

// ── Top critical/high vulns no período ─────────────────────────────────────
$topVulns = [];
foreach ($DB->request([
    'SELECT'  => ['plugin_name', 'severity_label', 'severity'],
    'COUNT'   => 'hosts_affected',
    'FROM'    => $vTable,
    'WHERE'   => array_merge($vWhere, ['severity' => ['>=', 3]]),
    'GROUPBY' => ['plugin_name', 'severity_label', 'severity'],
    'ORDER'   => ['severity DESC', 'hosts_affected DESC'],
    'LIMIT'   => 8,
]) as $row) {
    $topVulns[] = $row;
}

// ── Vulnerability discovery trend ──────────────────────────────────────────
$trend = [];
$oldest = date('Y-m-d 00:00:00', strtotime('-' . ($trendDays - 1) . ' days'));
for ($i = $trendDays - 1; $i >= 0; $i--) {
    $trend[date('Y-m-d', strtotime("-{$i} days"))] = 0;
}
foreach ($DB->request([
    'SELECT' => ['first_seen_at'],
    'FROM'   => Vulnerability::getTable(),
    'WHERE'  => ['NOT' => ['first_seen_at' => null], 'first_seen_at' => ['>=', $oldest]],
]) as $row) {
    $day = substr((string)($row['first_seen_at'] ?? ''), 0, 10);
    if (array_key_exists($day, $trend)) {
        $trend[$day]++;
    }
}

// ── Top hosts by vulnerability count ───────────────────────────────────────
$topHosts = [];
$hostTable = Host::getTable();
$vulnTable = Vulnerability::getTable();
$hostResult = $DB->doQuery(
    "SELECT h.hostname, h.ip, COUNT(v.id) AS total,"
    . " SUM(v.severity=4) AS critical_cnt, SUM(v.severity=3) AS high_cnt,"
    . " SUM(v.severity=2) AS medium_cnt"
    . " FROM `{$hostTable}` h"
    . " JOIN `{$vulnTable}` v ON v.plugin_nessusglpi_hosts_id = h.id"
    . " WHERE v.is_current = 1 AND v.first_seen_at >= " . $DB->quoteValue($cutoff)
    . " GROUP BY h.id, h.hostname, h.ip"
    . " ORDER BY critical_cnt DESC, high_cnt DESC, total DESC"
    . " LIMIT 10"
);
if ($hostResult) {
    while ($row = $hostResult->fetch_assoc()) {
        $topHosts[] = $row;
    }
}

// ── Vulns per scan ──────────────────────────────────────────────────────────
$vulnsPerScan = [];
$scanTable = Scan::getTable();
$scanResult = $DB->doQuery(
    "SELECT s.name, COUNT(v.id) AS total,"
    . " SUM(v.severity=4) AS critical_cnt, SUM(v.severity=3) AS high_cnt"
    . " FROM `{$scanTable}` s"
    . " JOIN `{$vulnTable}` v ON v.plugin_nessusglpi_scans_id = s.id"
    . " WHERE v.is_current = 1 AND v.first_seen_at >= " . $DB->quoteValue($cutoff)
    . " GROUP BY s.id, s.name"
    . " ORDER BY total DESC"
);
if ($scanResult) {
    while ($row = $scanResult->fetch_assoc()) {
        $vulnsPerScan[] = $row;
    }
}

// ── Risk Index (higher = more exposed) ─────────────────────────────────────
$riskPoints  = $criticalCount * 10 + $highCount * 3 + $sevTotals['medium'];
$maxR        = max(1, $totalHosts) * 20;
$riskIndex   = min(100, (int)round($riskPoints / $maxR * 100));

[$riskColor, $riskLabel, $riskBg] = match(true) {
    $riskIndex <= 25 => ['#22c55e', 'Exposição Baixa',      '#f0fdf4'],
    $riskIndex <= 50 => ['#f59e0b', 'Exposição Moderada',   '#fffbeb'],
    $riskIndex <= 75 => ['#ef4444', 'Exposição Alta',       '#fef2f2'],
    default          => ['#dc2626', 'Exposição Crítica',    '#fef2f2'],
};

$maxCount = max(1, ...array_values($trend));
$dayNames = ['Dom', 'Seg', 'Ter', 'Qua', 'Qui', 'Sex', 'Sáb'];
$maxSev   = max(1, $totalVulns);
$rootDoc  = (string)($CFG_GLPI['root_doc'] ?? '');

// ── Donut chart conic-gradient ──────────────────────────────────────────────
$donutStops = [];
$cumPct     = 0;
foreach (['critical', 'high', 'medium', 'low', 'info'] as $sevKey) {
    $cnt = $sevTotals[$sevKey] ?? 0;
    if ($cnt <= 0) continue;
    $pct  = $totalVulns > 0 ? ($cnt / $totalVulns * 100) : 0;
    $from = round($cumPct, 3);
    $to   = round($cumPct + $pct, 3);
    $donutStops[] = "{$sevColors[$sevKey]['bg']} {$from}% {$to}%";
    $cumPct += $pct;
}
$donutGradient = count($donutStops) > 0
    ? 'conic-gradient(' . implode(', ', $donutStops) . ')'
    : 'conic-gradient(#e2e8f0 0% 100%)';

Html::header('Nessus – Relatório Executivo', '', 'plugins', 'nessusglpi', 'report');
?>
<style>
/* ── Base ─────────────────────────────────────────────────────── */
.nr { margin: -20px -20px 0; background: #f0f4fa; min-height: calc(100vh - 60px);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; }

/* ── Toolbar ──────────────────────────────────────────────────── */
.nr-toolbar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
              background: #fff; border-bottom: 1px solid #e2e8f0;
              padding: 10px 28px; position: sticky; top: 0; z-index: 100; }
.nr-lbl { font-size: 12px; color: #94a3b8; font-weight: 500; }
.nr-pill { padding: 5px 18px; border-radius: 20px; text-decoration: none;
           font-size: 12px; font-weight: 700; border: none; cursor: pointer; }
.nr-pill.on  { background: #0087f5; color: #fff; }
.nr-pill.off { background: #e8f2fe; color: #0087f5; }
.nr-pill.off:hover { background: #d0e7fd; }
.nr-print { background: #041e42; color: #fff; padding: 7px 22px; border: none;
            border-radius: 7px; cursor: pointer; font-size: 13px; font-weight: 700;
            margin-left: auto; }
.nr-print:hover { background: #0a3a6b; }

/* ── Body ─────────────────────────────────────────────────────── */
.nr-body { max-width: 1320px; margin: 0 auto; padding: 24px 28px 32px; }

/* ── Hero ─────────────────────────────────────────────────────── */
.nr-hero { border-radius: 16px; margin-bottom: 20px; overflow: hidden;
           background: linear-gradient(135deg, #041e42 0%, #0a3a6b 55%, #0087f5 100%);
           display: flex; align-items: center; }
.nr-hero__left { flex: 1; padding: 36px 40px; color: #fff; }
.nr-hero__logo { font-size: 48px; font-weight: 900; letter-spacing: -3px; line-height: 1;
                 color: #fff; }
.nr-hero__logo span { color: #26ff93; }
.nr-hero__brand { font-size: 10px; letter-spacing: 6px; text-transform: uppercase;
                  color: #00c2d4; margin: 3px 0 16px; }
.nr-hero__title { font-size: 26px; font-weight: 700; margin: 0 0 6px; }
.nr-hero__period { font-size: 14px; color: #93c5fd; }
.nr-hero__last-scan { font-size: 12px; color: #64a8f8; margin-top: 4px; }
.nr-hero__right { display: flex; align-items: center; gap: 48px; padding: 36px 48px 36px 0; }

/* Gauge */
.nr-gauge-wrap { display: flex; flex-direction: column; align-items: center; gap: 10px; }
.nr-gauge { position: relative; width: 180px; height: 180px; flex-shrink: 0; }
.nr-gauge__ring { width: 180px; height: 180px; border-radius: 50%;
                  background: conic-gradient(<?= $riskColor ?> <?= $riskIndex ?>%, rgba(255,255,255,.12) 0%); }
.nr-gauge__inner { position: absolute; inset: 22px; background: #041e42;
                   border-radius: 50%; display: flex; flex-direction: column;
                   align-items: center; justify-content: center; }
.nr-gauge__pct { font-size: 38px; font-weight: 900; color: <?= $riskColor ?>;
                 line-height: 1; letter-spacing: -1px; }
.nr-gauge__sub { font-size: 9px; color: #93c5fd; text-transform: uppercase;
                 letter-spacing: 2px; margin-top: 2px; }
.nr-gauge__label { font-size: 14px; font-weight: 700; color: <?= $riskColor ?>; }

.nr-hero__stats { display: flex; flex-direction: column; gap: 20px; }
.nr-hstat { display: flex; flex-direction: column; gap: 2px; }
.nr-hstat__val { font-size: 32px; font-weight: 900; color: #fff; line-height: 1; }
.nr-hstat__val.red { color: #fca5a5; }
.nr-hstat__val.warn { color: #fde68a; }
.nr-hstat__lbl { font-size: 10px; color: #93c5fd; text-transform: uppercase; letter-spacing: 1.5px; }

/* ── Severity Exposure Panel v2 (donut + stat cards) ─────────── */
.nr-sev2 { background: #fff; border-radius: 12px; padding: 24px 26px; margin-bottom: 20px; }
.nr-section-title { font-size: 11px; font-weight: 700; letter-spacing: 3.5px;
                    text-transform: uppercase; color: #94a3b8; margin-bottom: 18px; }

/* 5 stat cards row */
.nr-sev2__stat-row { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 22px; }
.nr-sev2__stat {
    border-radius: 10px; overflow: hidden;
    box-shadow: 0 2px 10px -4px rgba(0,0,0,.18);
    transition: transform .15s, box-shadow .15s;
}
.nr-sev2__stat:hover { transform: translateY(-3px); box-shadow: 0 10px 26px -8px rgba(0,0,0,.26); }
.nr-sev2__stat-hdr { padding: 8px 14px; font-size: 10px; font-weight: 800;
                     letter-spacing: 2.5px; text-transform: uppercase; }
.nr-sev2__stat-body { padding: 10px 14px 14px; background: #fff; }
.nr-sev2__stat-num  { font-size: 2.6rem; font-weight: 900; line-height: 1; letter-spacing: -1px; }
.nr-sev2__stat-pct  { font-size: 11px; color: #94a3b8; font-weight: 600; margin-top: 5px; }

/* Donut + legend row */
.nr-sev2__lower { display: flex; gap: 36px; align-items: center; }
.nr-sev2__donut-wrap { flex-shrink: 0; display: flex; align-items: center; justify-content: center; }
.nr-sev2__donut {
    width: 168px; height: 168px; border-radius: 50%; position: relative;
    box-shadow: 0 6px 24px -8px rgba(0,0,0,.22);
}
.nr-sev2__donut-inner {
    position: absolute; inset: 30px; background: #f8fafc; border-radius: 50%;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    box-shadow: inset 0 2px 8px -4px rgba(0,0,0,.1);
}
.nr-sev2__donut-total { font-size: 1.9rem; font-weight: 900; color: #041e42; line-height: 1; }
.nr-sev2__donut-sub   { font-size: 0.64rem; color: #94a3b8; text-transform: uppercase;
                         letter-spacing: 1.5px; margin-top: 3px; }

/* Legend table */
.nr-sev2__legend { flex: 1; display: flex; flex-direction: column; gap: 9px; }
.nr-sev2__legend-row { display: flex; align-items: center; gap: 10px; }
.nr-sev2__legend-dot { width: 11px; height: 11px; border-radius: 50%; flex-shrink: 0; }
.nr-sev2__legend-name { font-weight: 700; font-size: 13px; color: #1e293b; min-width: 60px; }
.nr-sev2__legend-count { font-size: 14px; font-weight: 800; color: #041e42; min-width: 44px; text-align: right; }
.nr-sev2__legend-pct { font-size: 12px; color: #94a3b8; min-width: 38px; text-align: right; }
.nr-sev2__legend-bar { flex: 1; height: 7px; background: #f1f5f9; border-radius: 4px; overflow: hidden; margin-left: 4px; }
.nr-sev2__legend-bar-fill { height: 100%; border-radius: 4px; transition: width .55s; }

/* Distribution bar */
.nr-sev2__bar { margin-top: 22px; display: flex; height: 40px; border-radius: 8px;
                overflow: hidden; box-shadow: 0 2px 10px -4px rgba(0,0,0,.15); }
.nr-sev2__bar-seg {
    display: flex; align-items: center; justify-content: center;
    font-size: 11px; font-weight: 800; color: #fff; min-width: 26px;
    transition: filter .15s;
}
.nr-sev2__bar-seg:hover { filter: brightness(1.1); }

@media (max-width: 860px) {
    .nr-sev2__stat-row { grid-template-columns: repeat(3, 1fr); }
    .nr-sev2__lower    { flex-direction: column; align-items: stretch; }
}

/* ── KPI Cards ────────────────────────────────────────────────── */
.nr-kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }
.nr-kpi { background: #fff; border-radius: 12px; padding: 22px 24px; border-left: 4px solid transparent; overflow: hidden; }
.nr-kpi--total  { border-color: #0087f5; }
.nr-kpi--risk   { border-color: #8f233f; }
.nr-kpi--hosts  { border-color: #26ff93; }
.nr-kpi--ticket { border-color: #f6a14a; }
.nr-kpi__eye { font-size: 10px; font-weight: 700; letter-spacing: 2.5px;
               text-transform: uppercase; margin-bottom: 10px; }
.nr-kpi--total  .nr-kpi__eye { color: #0087f5; }
.nr-kpi--risk   .nr-kpi__eye { color: #8f233f; }
.nr-kpi--hosts  .nr-kpi__eye { color: #059669; }
.nr-kpi--ticket .nr-kpi__eye { color: #d97706; }
.nr-kpi__num { font-size: 44px; font-weight: 900; line-height: 1; margin-bottom: 4px; }
.nr-kpi--total  .nr-kpi__num { color: #041e42; }
.nr-kpi--risk   .nr-kpi__num { color: #8f233f; }
.nr-kpi--hosts  .nr-kpi__num { color: #065f46; }
.nr-kpi--ticket .nr-kpi__num { color: #92400e; }
.nr-kpi__num span { font-size: 18px; font-weight: 400; color: #94a3b8; }
.nr-kpi__sub { font-size: 12px; color: #64748b; line-height: 1.5; margin-top: 6px; }
.nr-kpi__tag { display: inline-block; padding: 2px 9px; border-radius: 20px;
               font-size: 11px; font-weight: 700; margin-top: 6px; }
.nr-tag-red  { background: #fee2e2; color: #991b1b; }
.nr-tag-warn { background: #fef3c7; color: #92400e; }
.nr-tag-ok   { background: #dcfce7; color: #166534; }
.nr-tag-blue { background: #dbeafe; color: #1d4ed8; }

/* ── Trend chart ──────────────────────────────────────────────── */
.nr-chart-card { background: #fff; border-radius: 12px; padding: 24px 26px; margin-bottom: 20px; overflow: hidden; }
.nr-bars { display: flex; align-items: flex-end; gap: 3px; height: 160px;
           background: #f0f4fa; border-radius: 10px; padding: 14px 12px 0; margin-bottom: 6px;
           overflow: hidden; }
.nr-bar-col { flex: 1; min-width: 0; display: flex; align-items: flex-end; height: 100%; overflow: hidden; }
.nr-bar { width: 100%; border-radius: 4px 4px 0 0; min-height: 3px; }
.nr-bar-labels { display: flex; gap: 3px; overflow: hidden; }
.nr-bar-lbl { flex: 1; min-width: 0; display: flex; flex-direction: column; align-items: center; font-size: 9px; gap: 1px; overflow: hidden; }
.nr-bar-lbl span { color: #94a3b8; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; display: block; text-align: center; }
.nr-bar-lbl strong { color: #041e42; font-size: 10px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 100%; display: block; text-align: center; }

/* ── Bottom grid ──────────────────────────────────────────────── */
.nr-grid2 { display: grid; grid-template-columns: 1.4fr 1fr; gap: 16px; margin-bottom: 20px; }
.nr-panel { background: #fff; border-radius: 12px; padding: 24px 26px; overflow: hidden; }
.nr-vuln-table { width: 100%; border-collapse: collapse; }
.nr-vuln-table th { font-size: 10px; text-transform: uppercase; letter-spacing: 1.5px;
                    color: #94a3b8; font-weight: 600; padding: 0 10px 10px 0;
                    border-bottom: 1px solid #f1f5f9; text-align: left; }
.nr-vuln-table td { padding: 9px 10px 9px 0; font-size: 12px; color: #334155;
                    border-bottom: 1px solid #f8fafc; vertical-align: middle; }
.nr-vuln-table tr:last-child td { border-bottom: none; }
.nr-vuln-name { max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 500; }
.nr-sbadge { display: inline-block; padding: 2px 8px; border-radius: 12px;
             font-size: 10px; font-weight: 700; white-space: nowrap; }
.nr-scan-row { display: flex; justify-content: space-between; align-items: center;
               padding: 10px 0; border-bottom: 1px solid #f1f5f9; font-size: 13px; }
.nr-scan-row:last-child { border-bottom: none; }
.nr-scan-name { color: #334155; font-weight: 500; overflow: hidden; text-overflow: ellipsis;
                white-space: nowrap; max-width: 220px; }
.nr-scan-meta { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.nr-scan-date { font-size: 11px; color: #94a3b8; }
.nr-dot-ok   { display:inline-block;width:7px;height:7px;border-radius:50%;background:#22c55e; }
.nr-dot-fail { display:inline-block;width:7px;height:7px;border-radius:50%;background:#ef4444; }

/* ── Footer ───────────────────────────────────────────────────── */
.nr-foot { background: linear-gradient(135deg, #041e42 0%, #0a3a6b 100%);
           border-radius: 12px; padding: 18px 28px;
           display: flex; justify-content: space-between; align-items: center; }
.nr-foot__l { font-size: 12px; color: #93c5fd; }
.nr-foot__r { font-size: 12px; color: #3b82f6; }

/* ── Print ────────────────────────────────────────────────────── */
@media print {
    .nr-toolbar, .glpi_header, .glpi_menu_container, .glpi_footer,
    #tab_menu, .breadcrumbs-container, nav { display: none !important; }
    .nr { margin: 0 !important; background: #fff; }
    .nr-body { padding: 12px; max-width: 100%; }
    .nr-hero, .nr-sev-card, .nr-kpi, .nr-chart-card, .nr-panel, .nr-foot { break-inside: avoid; }
    .nr-hero { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
</style>

<div class="nr">

  <!-- TOOLBAR -->
  <div class="nr-toolbar">
    <span class="nr-lbl">Período:</span>
    <?php foreach ([7 => '7 dias', 30 => '30 dias', 90 => '90 dias'] as $p => $lbl): ?>
    <a href="?period=<?= $p ?>" class="nr-pill <?= $period === $p ? 'on' : 'off' ?>"><?= $lbl ?></a>
    <?php endforeach; ?>
    <button class="nr-print" onclick="window.print()">&#8595;&nbsp; Exportar PDF</button>
  </div>

  <div class="nr-body">

    <!-- HERO -->
    <div class="nr-hero">
      <div class="nr-hero__left">
        <div class="nr-hero__logo">N<span>.</span></div>
        <div class="nr-hero__brand">Nessus &nbsp;by&nbsp; Tenable</div>
        <div class="nr-hero__title">Relatório Executivo de Vulnerabilidades</div>
        <div class="nr-hero__period">Período: <?= $h($periodLabel) ?></div>
        <?php if ($lastScanAt): ?>
        <div class="nr-hero__last-scan">Último scan: <?= $h(substr($lastScanAt, 0, 16)) ?></div>
        <?php endif; ?>
      </div>
      <div class="nr-hero__right">
        <div class="nr-gauge-wrap">
          <div class="nr-gauge">
            <div class="nr-gauge__ring"></div>
            <div class="nr-gauge__inner">
              <div class="nr-gauge__pct"><?= $riskIndex ?>%</div>
              <div class="nr-gauge__sub">risco</div>
            </div>
          </div>
          <div class="nr-gauge__label"><?= $h($riskLabel) ?></div>
        </div>
        <div class="nr-hero__stats">
          <div class="nr-hstat">
            <div class="nr-hstat__val"><?= $totalVulns ?></div>
            <div class="nr-hstat__lbl">vulnerabilidades</div>
          </div>
          <div class="nr-hstat">
            <div class="nr-hstat__val <?= $critHighCount > 0 ? 'red' : '' ?>"><?= $critHighCount ?></div>
            <div class="nr-hstat__lbl">críticas + altas</div>
          </div>
          <div class="nr-hstat">
            <div class="nr-hstat__val"><?= $totalHosts ?></div>
            <div class="nr-hstat__lbl">hosts avaliados</div>
          </div>
        </div>
      </div>
    </div>

    <!-- SEVERITY EXPOSURE PANEL v2 (Grafana v5 style) -->
    <div class="nr-sev2">
      <div class="nr-section-title">Exposição por Severidade</div>

      <!-- 5 stat cards -->
      <div class="nr-sev2__stat-row">
        <?php foreach ($sevTotals as $key => $count):
          $cl  = $sevColors[$key];
          $lbl = $sevLabels[$key];
          $pct = $totalVulns > 0 ? (int)round($count / $totalVulns * 100) : 0;
        ?>
        <div class="nr-sev2__stat">
          <div class="nr-sev2__stat-hdr" style="background:<?= $cl['bg'] ?>;color:<?= $cl['fg'] ?>"><?= $h($lbl) ?></div>
          <div class="nr-sev2__stat-body">
            <div class="nr-sev2__stat-num" style="color:<?= $cl['bg'] ?>"><?= $count ?></div>
            <div class="nr-sev2__stat-pct"><?= $pct ?>% do total</div>
          </div>
        </div>
        <?php endforeach; ?>
      </div>

      <!-- Donut + legend -->
      <div class="nr-sev2__lower">
        <div class="nr-sev2__donut-wrap">
          <div class="nr-sev2__donut" style="background:<?= $donutGradient ?>">
            <div class="nr-sev2__donut-inner">
              <div class="nr-sev2__donut-total"><?= $totalVulns ?></div>
              <div class="nr-sev2__donut-sub">vulns</div>
            </div>
          </div>
        </div>
        <div class="nr-sev2__legend">
          <?php foreach ($sevTotals as $key => $count):
            if ($count === 0) continue;
            $cl  = $sevColors[$key];
            $lbl = $sevLabels[$key];
            $pct = $totalVulns > 0 ? (int)round($count / $totalVulns * 100) : 0;
          ?>
          <div class="nr-sev2__legend-row">
            <span class="nr-sev2__legend-dot" style="background:<?= $cl['bg'] ?>"></span>
            <span class="nr-sev2__legend-name"><?= $h($lbl) ?></span>
            <span class="nr-sev2__legend-count"><?= $count ?></span>
            <span class="nr-sev2__legend-pct"><?= $pct ?>%</span>
            <div class="nr-sev2__legend-bar">
              <div class="nr-sev2__legend-bar-fill" style="width:<?= $pct ?>%;background:<?= $cl['bg'] ?>"></div>
            </div>
          </div>
          <?php endforeach; ?>
        </div>
      </div>

      <!-- Distribution bar -->
      <div class="nr-sev2__bar">
        <?php foreach ($sevTotals as $key => $count):
          if ($count <= 0) continue;
          $pctF = $totalVulns > 0 ? max(1, round($count / $totalVulns * 100, 2)) : 0;
          $cl   = $sevColors[$key];
          $lbl  = $sevLabels[$key];
        ?>
        <div class="nr-sev2__bar-seg" style="flex:<?= $pctF ?> 0 0;background:<?= $cl['bg'] ?>" title="<?= $h($lbl) ?>: <?= $count ?>">
          <?php if ($pctF >= 8): ?><?= $count ?><?php endif; ?>
        </div>
        <?php endforeach; ?>
      </div>
    </div>

    <!-- KPI CARDS -->
    <div class="nr-kpis">
      <div class="nr-kpi nr-kpi--total">
        <div class="nr-kpi__eye">Total de Vulnerabilidades</div>
        <div class="nr-kpi__num"><?= $totalVulns ?><span> ativas</span></div>
        <div class="nr-kpi__sub">Críticas: <?= $criticalCount ?> &nbsp;·&nbsp; Altas: <?= $highCount ?> &nbsp;·&nbsp; Médias: <?= $sevTotals['medium'] ?></div>
        <?php if ($criticalCount > 0): ?>
        <span class="nr-kpi__tag nr-tag-red"><?= $criticalCount ?> críticas</span>
        <?php else: ?>
        <span class="nr-kpi__tag nr-tag-ok">Nenhuma crítica</span>
        <?php endif; ?>
      </div>
      <div class="nr-kpi nr-kpi--risk">
        <div class="nr-kpi__eye">Críticas + Altas</div>
        <div class="nr-kpi__num"><?= $critHighCount ?><span> vulns</span></div>
        <div class="nr-kpi__sub">Prioridade máxima de correção</div>
        <?php if ($critHighCount > 0): ?>
        <span class="nr-kpi__tag nr-tag-red">Ação imediata</span>
        <?php else: ?>
        <span class="nr-kpi__tag nr-tag-ok">Nenhuma</span>
        <?php endif; ?>
      </div>
      <div class="nr-kpi nr-kpi--hosts">
        <div class="nr-kpi__eye">Hosts Avaliados</div>
        <div class="nr-kpi__num"><?= $totalHosts ?><span> hosts</span></div>
        <div class="nr-kpi__sub">Vinculados ao GLPI: <?= $linkedHosts ?></div>
        <?php if ($unlinkedHosts > 0): ?>
        <span class="nr-kpi__tag nr-tag-warn"><?= $unlinkedHosts ?> sem vínculo</span>
        <?php else: ?>
        <span class="nr-kpi__tag nr-tag-ok">Todos vinculados</span>
        <?php endif; ?>
      </div>
      <div class="nr-kpi nr-kpi--ticket">
        <div class="nr-kpi__eye">Tickets Abertos</div>
        <div class="nr-kpi__num"><?= $withTickets ?><span> tickets</span></div>
        <div class="nr-kpi__sub">Chamados criados automaticamente</div>
        <span class="nr-kpi__tag nr-tag-blue"><?= count($scans) ?> scans ativos</span>
      </div>
    </div>

    <!-- TREND CHART -->
    <div class="nr-chart-card">
      <div class="nr-section-title">Vulnerabilidades Detectadas — últimos <?= $trendDays ?> dias</div>
      <div class="nr-bars">
        <?php foreach ($trend as $date => $count):
          $barH  = (int)max(3, round($count / $maxCount * 100));
          $today = date('Y-m-d');
          $bg = match(true) {
              $count === 0  => '#e2e8f0',
              $count <= 5   => '#6aa7df',
              $count <= 20  => '#d94f4f',
              default       => '#8f233f',
          };
          $outline = ($date === $today) ? 'outline:2px solid #0087f5;outline-offset:2px;' : '';
        ?>
        <div class="nr-bar-col">
          <div class="nr-bar" style="height:<?= $barH ?>%;background:<?= $bg ?>;<?= $outline ?>"></div>
        </div>
        <?php endforeach; ?>
      </div>
      <div class="nr-bar-labels">
        <?php foreach ($trend as $date => $count):
          $lbl = $dayNames[(int)date('w', strtotime($date))];
        ?>
        <div class="nr-bar-lbl"><span><?= $lbl ?></span><strong><?= $count > 0 ? $count : '' ?></strong></div>
        <?php endforeach; ?>
      </div>
    </div>

    <!-- BOTTOM: Top vulns + Scans -->
    <div class="nr-grid2">

      <!-- Top Critical/High vulns -->
      <div class="nr-panel">
        <div class="nr-section-title">Top Vulnerabilidades Críticas e Altas</div>
        <?php if (empty($topVulns)): ?>
        <div style="padding:20px;text-align:center;color:#22c55e;font-size:13px;font-weight:600">
          &#10003; Nenhuma vulnerabilidade crítica ou alta detectada
        </div>
        <?php else: ?>
        <table class="nr-vuln-table">
          <thead><tr><th>Vulnerabilidade</th><th>Sev.</th><th>Hosts</th></tr></thead>
          <tbody>
          <?php foreach ($topVulns as $v):
            $vKey = strtolower(trim((string)($v['severity_label'] ?? '')));
            $mapped = $keyMap[$vKey] ?? 'high';
            $cl = $sevColors[$mapped];
            $name = (string)($v['plugin_name'] ?? '—');
          ?>
          <tr>
            <td><div class="nr-vuln-name" title="<?= $h($name) ?>"><?= $h($name) ?></div></td>
            <td><span class="nr-sbadge" style="background:<?= $cl['bg'] ?>;color:<?= $cl['fg'] ?>"><?= $h($sevLabels[$mapped] ?? $vKey) ?></span></td>
            <td style="font-weight:700;color:#041e42;text-align:right"><?= (int)($v['hosts_affected'] ?? 0) ?></td>
          </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        <?php endif; ?>
      </div>

      <!-- Scans -->
      <div class="nr-panel">
        <div class="nr-section-title">Scans Configurados</div>
        <?php if (empty($scans)): ?>
        <div style="padding:20px;text-align:center;color:#94a3b8;font-size:13px">Nenhum scan configurado</div>
        <?php else: ?>
        <?php foreach ($scans as $scan):
          $ok = ($scan['last_sync_status'] ?? '') === 'success';
          $date = substr((string)($scan['last_scan_at'] ?? ''), 0, 10);
          $name = (string)($scan['name'] ?? '—');
        ?>
        <div class="nr-scan-row">
          <span class="nr-scan-name" title="<?= $h($name) ?>"><?= $h($name) ?></span>
          <div class="nr-scan-meta">
            <span class="nr-scan-date"><?= $date ?: '—' ?></span>
            <span class="<?= $ok ? 'nr-dot-ok' : 'nr-dot-fail' ?>"></span>
          </div>
        </div>
        <?php endforeach; ?>
        <?php endif; ?>
      </div>

    </div>

    <!-- TOP HOSTS EM RISCO -->
    <div class="nr-panel" style="margin-bottom:20px">
      <div class="nr-section-title">Top Hosts em Risco</div>
      <?php if (empty($topHosts)): ?>
      <div style="padding:20px;text-align:center;color:#22c55e;font-size:13px;font-weight:600">&#10003; Nenhum host com vulnerabilidades detectadas</div>
      <?php else: ?>
      <table class="nr-vuln-table" style="table-layout:fixed;width:100%">
        <thead>
          <tr>
            <th style="width:34%">Hostname</th>
            <th style="width:18%">IP</th>
            <th style="width:14%;text-align:center">Críticas</th>
            <th style="width:14%;text-align:center">Altas</th>
            <th style="width:12%;text-align:center">Médias</th>
            <th style="width:8%;text-align:right">Total</th>
          </tr>
        </thead>
        <tbody>
        <?php foreach ($topHosts as $i => $host):
          $hname   = (string)($host['hostname'] ?? '');
          $ip      = (string)($host['ip']       ?? '—');
          $crit    = (int)($host['critical_cnt'] ?? 0);
          $high    = (int)($host['high_cnt']     ?? 0);
          $med     = (int)($host['medium_cnt']   ?? 0);
          $tot     = (int)($host['total']        ?? 0);
          $rowBg   = $i % 2 === 0 ? '' : 'background:#f8fafc';
        ?>
        <tr style="<?= $rowBg ?>">
          <td>
            <div style="display:flex;align-items:center;gap:8px">
              <?php if ($crit > 0): ?>
              <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#8f233f;flex-shrink:0"></span>
              <?php elseif ($high > 0): ?>
              <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#d94f4f;flex-shrink:0"></span>
              <?php else: ?>
              <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#f6a14a;flex-shrink:0"></span>
              <?php endif; ?>
              <span style="font-weight:600;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="<?= $h($hname) ?>"><?= $h($hname ?: '—') ?></span>
            </div>
          </td>
          <td style="font-size:11px;color:#64748b;font-family:monospace"><?= $h($ip) ?></td>
          <td style="text-align:center">
            <?php if ($crit > 0): ?>
            <span style="display:inline-block;padding:2px 10px;border-radius:12px;background:#8f233f;color:#fff;font-size:12px;font-weight:800"><?= $crit ?></span>
            <?php else: ?>
            <span style="color:#cbd5e1">—</span>
            <?php endif; ?>
          </td>
          <td style="text-align:center">
            <?php if ($high > 0): ?>
            <span style="display:inline-block;padding:2px 10px;border-radius:12px;background:#d94f4f;color:#fff;font-size:12px;font-weight:800"><?= $high ?></span>
            <?php else: ?>
            <span style="color:#cbd5e1">—</span>
            <?php endif; ?>
          </td>
          <td style="text-align:center;font-size:13px;color:#92400e;font-weight:600"><?= $med > 0 ? $med : '<span style="color:#cbd5e1">—</span>' ?></td>
          <td style="text-align:right;font-weight:800;font-size:15px;color:#041e42"><?= $tot ?></td>
        </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
      <?php endif; ?>
    </div>

    <!-- VULNS POR SCAN -->
    <?php if (!empty($vulnsPerScan)): ?>
    <?php $maxScanTotal = max(1, ...array_column($vulnsPerScan, 'total')); ?>
    <div class="nr-panel" style="margin-bottom:20px">
      <div class="nr-section-title">Vulnerabilidades por Scan</div>
      <?php foreach ($vulnsPerScan as $sv):
        $sname  = (string)($sv['name']         ?? '—');
        $tot    = (int)($sv['total']        ?? 0);
        $crit   = (int)($sv['critical_cnt'] ?? 0);
        $high   = (int)($sv['high_cnt']     ?? 0);
        $pctW   = (int)max(1, round($tot / $maxScanTotal * 100));
        $barBg  = $crit > 0 ? '#8f233f' : ($high > 0 ? '#d94f4f' : '#6aa7df');
      ?>
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px">
        <div style="min-width:0;flex:0 0 260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px;font-weight:600;color:#1e293b" title="<?= $h($sname) ?>"><?= $h($sname) ?></div>
        <div style="flex:1;background:#f1f5f9;border-radius:6px;height:26px;overflow:hidden">
          <div style="background:<?= $barBg ?>;width:<?= $pctW ?>%;height:100%;border-radius:6px;display:flex;align-items:center;padding-left:10px;transition:width .5s">
            <?php if ($pctW >= 10): ?>
            <span style="font-size:12px;font-weight:800;color:#fff"><?= $tot ?></span>
            <?php endif; ?>
          </div>
        </div>
        <?php if ($pctW < 10): ?>
        <span style="font-weight:800;font-size:13px;color:#1e293b;min-width:30px"><?= $tot ?></span>
        <?php endif; ?>
        <div style="min-width:120px;display:flex;gap:6px;justify-content:flex-end;flex-shrink:0">
          <?php if ($crit > 0): ?>
          <span style="padding:1px 8px;border-radius:10px;background:#8f233f;color:#fff;font-size:11px;font-weight:700"><?= $crit ?> críticas</span>
          <?php endif; ?>
          <?php if ($high > 0): ?>
          <span style="padding:1px 8px;border-radius:10px;background:#d94f4f;color:#fff;font-size:11px;font-weight:700"><?= $high ?> altas</span>
          <?php endif; ?>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <!-- FOOTER -->
    <div class="nr-foot">
      <div class="nr-foot__l">Gerado automaticamente em <?= $h($genAt) ?> &bull; Plugin Nessus para GLPI</div>
      <div class="nr-foot__r">Período: <?= $h($periodLabel) ?></div>
    </div>

  </div>
</div>
<?php
Html::footer();
