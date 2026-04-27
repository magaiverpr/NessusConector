<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncJobService;

include('../../../inc/includes.php');

Session::checkRight(Scan::$rightname, UPDATE);
Html::header_nocache();

$scanId = (int) ($_POST['id'] ?? 0);
if (!Scan::canAccessScanId($scanId)) {
    http_response_code(403);
    echo json_encode([
        'ok'      => false,
        'message' => __('You do not have permission to access this scan.', 'nessusglpi'),
    ], JSON_THROW_ON_ERROR);
    exit;
}

$service = new SyncJobService();

try {
    $jobId = $service->queueScan($scanId);
    echo json_encode([
        'ok'     => true,
        'job_id' => $jobId,
    ], JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    http_response_code(400);
    echo json_encode([
        'ok'      => false,
        'message' => $e->getMessage(),
    ], JSON_THROW_ON_ERROR);
}
