<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncJobService;

include('../../../inc/includes.php');

Session::checkRight(Scan::$rightname, UPDATE);
Html::header_nocache();
header('Content-Type: application/json; charset=utf-8');

$entityIds = Scan::getVisibleEntityIds();
$service   = new SyncJobService();
// Read-only status poll: served over GET so it is exempt from CSRF validation
// (GLPI only enforces CSRF on unsafe methods). This prevents the polling loop
// from consuming the page's one-time CSRF token, which previously broke both
// the queue poll and the per-scan sync forms that share that token.
$finishedSince = trim((string) ($_GET['since'] ?? $_POST['since'] ?? ''));

$recentJobs = $service->getRecentlyFinishedJobs($entityIds, $finishedSince);

$payload = [
    'ok'        => true,
    'processed' => false,
    'remaining' => (int) $service->countPendingJobs($entityIds),
    'open'      => (int) $service->countOpenJobs($entityIds),
    'job'       => null,
    'jobs'      => [],
    'checked_at' => date('Y-m-d H:i:s'),
];

foreach ($recentJobs as $jobRow) {
    $scanInternalId = (int) ($jobRow['plugin_nessusglpi_scans_id'] ?? 0);
    $scan = new Scan();
    $scanRow = $scanInternalId > 0 && $scan->getFromDB($scanInternalId) ? $scan->fields : [];

    $lastSyncStatus = (string) ($scanRow['last_sync_status'] ?? ($jobRow['status'] ?? ''));
    $lastSyncAt     = (string) ($scanRow['last_sync_at'] ?? '');

    $payload['jobs'][] = [
        'job_id'             => (int) ($jobRow['id'] ?? 0),
        'scan_internal_id'   => $scanInternalId,
        'scan_name'          => (string) ($scanRow['name'] ?? ('#' . $scanInternalId)),
        'status'             => (string) ($jobRow['status'] ?? ''),
        'message'            => (string) ($jobRow['message'] ?? ''),
        'run_id'             => isset($jobRow['run_id']) ? (int) $jobRow['run_id'] : null,
        'last_sync_status'   => $lastSyncStatus,
        'last_sync_at'       => $lastSyncAt,
        'last_sync_bucket'   => Scan::statusBucket($lastSyncStatus),
        'last_sync_label'    => Scan::statusLabel($lastSyncStatus),
        'last_sync_relative' => Scan::relativeDate($lastSyncAt),
    ];
}

if ($payload['jobs'] !== []) {
    $payload['job'] = $payload['jobs'][array_key_last($payload['jobs'])];
}

echo json_encode($payload, JSON_THROW_ON_ERROR);
