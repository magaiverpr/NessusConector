<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

/**
 * Vulnerability trend analytics: point-in-time backlog comparison, new vs
 * resolved over time, and per-scan run history. All read-only aggregations
 * over glpi_plugin_nessusglpi_vulnerabilities / _scan_runs.
 */
class Trends
{
    /** Severity order (label => rank). */
    public const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

    public static function table(): string
    {
        return 'glpi_plugin_nessusglpi_vulnerabilities';
    }

    /** Selectable comparison windows (days => human label). */
    public static function windows(): array
    {
        return [
            30  => '30 dias',
            90  => '90 dias',
            180 => '6 meses',
            365 => '1 ano',
            540 => '18 meses',
        ];
    }

    private static function emptySeverityMap(): array
    {
        return array_fill_keys(self::SEVERITIES, 0);
    }

    /**
     * Counts grouped by severity_label for an arbitrary WHERE clause.
     *
     * @return array{total:int,by_severity:array<string,int>}
     */
    private static function countBy(string $where): array
    {
        global $DB;

        $out = ['total' => 0, 'by_severity' => self::emptySeverityMap()];

        if (!$DB->tableExists(self::table())) {
            return $out;
        }

        $res = $DB->doQuery(
            'SELECT severity_label AS sev, COUNT(*) AS c FROM `' . self::table() . '`'
            . ' WHERE ' . $where . ' GROUP BY severity_label'
        );
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $sev = (string) $row['sev'];
                $cnt = (int) $row['c'];
                $out['total'] += $cnt;
                if (isset($out['by_severity'][$sev])) {
                    $out['by_severity'][$sev] += $cnt;
                }
            }
        }

        return $out;
    }

    /** Current open backlog (is_current = 1). */
    public static function currentTotals(): array
    {
        return self::countBy('is_current = 1');
    }

    /** Earliest first_seen_at in the dataset (how far back history goes). */
    public static function dataSince(): ?string
    {
        global $DB;

        if (!$DB->tableExists(self::table())) {
            return null;
        }

        $res = $DB->doQuery('SELECT MIN(first_seen_at) AS m FROM `' . self::table() . '`');
        if ($res && ($row = $res->fetch_assoc())) {
            return !empty($row['m']) ? (string) $row['m'] : null;
        }

        return null;
    }

    /**
     * Point-in-time comparison: backlog now vs `$days` ago, plus opened/resolved
     * within the window. "then" = vulns first seen on/before the cutoff that were
     * still open at the cutoff (current, or resolved after it).
     */
    public static function comparison(int $days): array
    {
        $days   = max(1, $days);
        $cutoff = "DATE_SUB(NOW(), INTERVAL {$days} DAY)";

        $now      = self::currentTotals();
        $then     = self::countBy("first_seen_at <= {$cutoff} AND (is_current = 1 OR last_seen_at >= {$cutoff})");
        $opened   = self::countBy("first_seen_at >= {$cutoff}");
        $resolved = self::countBy("is_current = 0 AND last_seen_at >= {$cutoff}");

        $bySeverity = [];
        foreach (self::SEVERITIES as $sev) {
            $n = $now['by_severity'][$sev];
            $t = $then['by_severity'][$sev];
            $bySeverity[$sev] = [
                'now'   => $n,
                'then'  => $t,
                'delta' => $n - $t,
            ];
        }

        $dataSince    = self::dataSince();
        $coversWindow = $dataSince !== null && strtotime($dataSince) <= (time() - $days * 86400);

        return [
            'days'         => $days,
            'now'          => $now['total'],
            'then'         => $then['total'],
            'delta'        => $now['total'] - $then['total'],
            'opened'       => $opened['total'],
            'resolved'     => $resolved['total'],
            'by_severity'  => $bySeverity,
            'data_since'   => $dataSince,
            'covers_window' => $coversWindow,
        ];
    }

    /**
     * Opened (by first_seen) and resolved (by last_seen) bucketed by month over
     * the window, for a column chart.
     *
     * @return array<int,array{label:string,opened:int,resolved:int}>
     */
    public static function timeline(int $days): array
    {
        global $DB;

        if (!$DB->tableExists(self::table())) {
            return [];
        }

        $days   = max(1, $days);
        $cutoff = "DATE_SUB(NOW(), INTERVAL {$days} DAY)";
        $buckets = [];

        $opened = $DB->doQuery(
            "SELECT DATE_FORMAT(first_seen_at, '%Y-%m') AS bucket, COUNT(*) AS c FROM `" . self::table() . "`"
            . " WHERE first_seen_at >= {$cutoff} GROUP BY bucket ORDER BY bucket"
        );
        if ($opened) {
            while ($row = $opened->fetch_assoc()) {
                $b = (string) $row['bucket'];
                $buckets[$b]['opened'] = (int) $row['c'];
            }
        }

        $resolved = $DB->doQuery(
            "SELECT DATE_FORMAT(last_seen_at, '%Y-%m') AS bucket, COUNT(*) AS c FROM `" . self::table() . "`"
            . " WHERE is_current = 0 AND last_seen_at >= {$cutoff} GROUP BY bucket ORDER BY bucket"
        );
        if ($resolved) {
            while ($row = $resolved->fetch_assoc()) {
                $b = (string) $row['bucket'];
                $buckets[$b]['resolved'] = (int) $row['c'];
            }
        }

        ksort($buckets);

        $out = [];
        foreach ($buckets as $label => $vals) {
            $out[] = [
                'label'    => $label,
                'opened'   => (int) ($vals['opened'] ?? 0),
                'resolved' => (int) ($vals['resolved'] ?? 0),
            ];
        }

        return $out;
    }

    /**
     * Recent scan runs with the delta in vulnerabilities_found vs the previous
     * run of the same scan ("current scan vs older scan").
     *
     * @return array<int,array{run_id:int,scan_id:int,scan_name:string,started_at:string,hosts:int,vulns:int,delta:?int}>
     */
    public static function scanRuns(int $limit = 15): array
    {
        global $DB;

        $runsTable  = 'glpi_plugin_nessusglpi_scan_runs';
        $scansTable = 'glpi_plugin_nessusglpi_scans';

        if (!$DB->tableExists($runsTable)) {
            return [];
        }

        $hasScans = $DB->tableExists($scansTable);
        $rows = [];
        foreach ($DB->request([
            'FROM'  => $runsTable,
            'ORDER' => ['started_at ASC', 'id ASC'],
        ]) as $r) {
            $rows[] = $r;
        }

        // delta vs the previous run of the same scan. Re-imports can create new
        // scan_ids for the same Nessus scan, so we group by scan NAME (falling
        // back to the id) to keep "current run vs older run" meaningful.
        $prevByScan = [];
        $enriched   = [];
        foreach ($rows as $r) {
            $scanId = (int) ($r['plugin_nessusglpi_scans_id'] ?? 0);
            $vulns  = (int) ($r['vulnerabilities_found'] ?? 0);

            $scanName = '#' . $scanId;
            if ($hasScans && $scanId > 0) {
                $s = $DB->request(['SELECT' => ['name'], 'FROM' => $scansTable, 'WHERE' => ['id' => $scanId], 'LIMIT' => 1])->current();
                if ($s && !empty($s['name'])) {
                    $scanName = (string) $s['name'];
                }
            }

            $key   = $scanName;
            $delta = isset($prevByScan[$key]) ? ($vulns - $prevByScan[$key]) : null;
            $prevByScan[$key] = $vulns;

            $enriched[] = [
                'run_id'     => (int) $r['id'],
                'scan_id'    => $scanId,
                'scan_name'  => $scanName,
                'started_at' => (string) ($r['started_at'] ?? ''),
                'hosts'      => (int) ($r['hosts_found'] ?? 0),
                'vulns'      => $vulns,
                'delta'      => $delta,
            ];
        }

        // most recent first, capped
        $enriched = array_reverse($enriched);
        return array_slice($enriched, 0, max(1, $limit));
    }
}
