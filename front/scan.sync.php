<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncJobService;

include('../../../inc/includes.php');

Session::checkRight(Scan::$rightname, UPDATE);

$scanId = (int) ($_POST['id'] ?? 0);
if (!Scan::canAccessScanId($scanId)) {
    Html::displayRightError();
}

try {
    $jobId = (new SyncJobService())->queueScan($scanId);
    Session::addMessageAfterRedirect(sprintf(__('Synchronization queued. Job #%d created.', 'nessusglpi'), $jobId));
} catch (Throwable $e) {
    Session::addMessageAfterRedirect($e->getMessage(), true);
}

Html::redirect('scan.php');
