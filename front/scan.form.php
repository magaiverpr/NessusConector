<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\NessusClient;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncJobService;

include('../../../inc/includes.php');

function nessusglpi_redirect_to_scan_list(): never
{
    global $CFG_GLPI;

    $target = rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/') . '/plugins/nessusglpi/front/scan.php';
    header('Location: ' . $target);
    exit;
}

Session::checkRight(Scan::$rightname, READ);

$scan = new Scan();
$message = null;
$messageType = 'info';
$currentId = (int) ($_GET['id'] ?? ($_POST['id'] ?? 0));

if ($currentId > 0 && !Scan::canAccessScanId($currentId)) {
    Html::displayRightError();
}

if (isset($_POST['add'])) {
    Session::checkRight(Scan::$rightname, CREATE);

    try {
        global $DB;

        $scanId = trim((string) ($_POST['scan_id'] ?? ''));
        if ($scanId === '') {
            throw new RuntimeException(__('Scan ID is required.', 'nessusglpi'));
        }

        $encodedImportSeverities = Scan::encodeImportSeverities($_POST['import_severities'] ?? []);

        $scanDetails = (new NessusClient())->getScanDetails($scanId);
        $scanName = trim((string) ($scanDetails['info']['name'] ?? $scanDetails['name'] ?? ''));
        if ($scanName === '') {
            $scanName = sprintf(__('Scan %s', 'nessusglpi'), $scanId);
        }

        $newId = $scan->add([
            'scan_id'           => $scanId,
            'name'              => $scanName,
            'entities_id'       => (int) Session::getActiveEntity(),
            'import_severities' => $encodedImportSeverities,
        ]);

        if (!$newId) {
            throw new RuntimeException(__('Unable to create the scan record.', 'nessusglpi'));
        }

        $DB->update(Scan::getTable(), [
            'import_severities' => $encodedImportSeverities,
        ], [
            'id' => (int) $newId,
        ]);

        $jobId = (new SyncJobService())->queueScan((int) $newId);
        Session::addMessageAfterRedirect(
            sprintf(
                __('Scan created successfully. Initial synchronization queued as job #%d.', 'nessusglpi'),
                $jobId
            )
        );

        nessusglpi_redirect_to_scan_list();
    } catch (Throwable $e) {
        $message = $e->getMessage();
        $messageType = 'error';
        $scan->fields['scan_id'] = (string) ($_POST['scan_id'] ?? '');
        $scan->fields['entities_id'] = (int) Session::getActiveEntity();
        $scan->fields['import_severities'] = Scan::encodeImportSeverities($_POST['import_severities'] ?? []);
    }
}

if (isset($_POST['update'])) {
    Session::checkRight(Scan::$rightname, UPDATE);

    try {
        global $DB;

        $scanRecordId = (int) ($_POST['id'] ?? 0);
        if (!Scan::canAccessScanId($scanRecordId)) {
            Html::displayRightError();
        }

        $scanId = trim((string) ($_POST['scan_id'] ?? ''));
        if ($scanId === '') {
            throw new RuntimeException(__('Scan ID is required.', 'nessusglpi'));
        }

        $encodedImportSeverities = Scan::encodeImportSeverities($_POST['import_severities'] ?? []);

        $scanDetails = (new NessusClient())->getScanDetails($scanId);
        $scanName = trim((string) ($scanDetails['info']['name'] ?? $scanDetails['name'] ?? ''));
        if ($scanName === '') {
            $scanName = sprintf(__('Scan %s', 'nessusglpi'), $scanId);
        }

        $scan->update([
            'id'                => $scanRecordId,
            'scan_id'           => $scanId,
            'name'              => $scanName,
            'entities_id'       => (int) Session::getActiveEntity(),
            'import_severities' => $encodedImportSeverities,
        ]);

        $DB->update(Scan::getTable(), [
            'scan_id'           => $scanId,
            'name'              => $scanName,
            'entities_id'       => (int) Session::getActiveEntity(),
            'import_severities' => $encodedImportSeverities,
        ], [
            'id' => $scanRecordId,
        ]);

        Session::addMessageAfterRedirect(__('Scan updated successfully.', 'nessusglpi'));
        nessusglpi_redirect_to_scan_list();
    } catch (Throwable $e) {
        $message = $e->getMessage();
        $messageType = 'error';
        $scan->fields['id'] = (int) ($_POST['id'] ?? 0);
        $scan->fields['scan_id'] = (string) ($_POST['scan_id'] ?? '');
        $scan->fields['entities_id'] = (int) Session::getActiveEntity();
        $scan->fields['import_severities'] = Scan::encodeImportSeverities($_POST['import_severities'] ?? []);
    }
}

Html::header(__('Nessus scan', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');
$scan->showForm($currentId, [
    'message'      => $message,
    'message_type' => $messageType,
]);
Html::footer();
