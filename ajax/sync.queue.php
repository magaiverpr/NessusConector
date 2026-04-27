<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncJobService;

include('../../../inc/includes.php');

Session::checkRight(Scan::$rightname, UPDATE);
Html::header_nocache();

$service = new SyncJobService();
$result = $service->processNextPendingJob(Scan::getVisibleEntityIds());

echo json_encode([
    'ok'        => true,
    'processed' => $result !== null,
    'job'       => $result,
], JSON_THROW_ON_ERROR);
