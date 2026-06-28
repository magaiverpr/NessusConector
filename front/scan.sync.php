<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncJobService;

include('../../../inc/includes.php');

Session::checkRight(Scan::$rightname, UPDATE);
// CSRF is validated by GLPI 11's kernel (CheckCsrfListener) before this script runs.

$isAjax = (strtolower((string) ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '')) === 'xmlhttprequest')
    || (strpos((string) ($_SERVER['HTTP_ACCEPT'] ?? ''), 'application/json') !== false);

$scanId = (int) ($_POST['id'] ?? 0);

if (!Scan::canAccessScanId($scanId)) {
    if ($isAjax) {
        http_response_code(403);
        Html::header_nocache();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'ok'      => false,
            'message' => __('You are not allowed to access this scan.', 'nessusglpi'),
        ], JSON_THROW_ON_ERROR);
        return;
    }
    Html::displayRightError();
}

try {
    $jobId = (new SyncJobService())->queueScan($scanId);

    if ($isAjax) {
        Html::header_nocache();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'ok'       => true,
            'job_id'   => $jobId,
            'scan_id'  => $scanId,
            'message'  => sprintf(__('Synchronization queued. Job #%d created.', 'nessusglpi'), $jobId),
        ], JSON_THROW_ON_ERROR);
        return;
    }

    Session::addMessageAfterRedirect(sprintf(__('Synchronization queued. Job #%d created.', 'nessusglpi'), $jobId));
} catch (Throwable $e) {
    if ($isAjax) {
        http_response_code(400);
        Html::header_nocache();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode([
            'ok'      => false,
            'message' => $e->getMessage(),
        ], JSON_THROW_ON_ERROR);
        return;
    }

    Session::addMessageAfterRedirect($e->getMessage(), true);
}

Html::redirect('scan.php');
