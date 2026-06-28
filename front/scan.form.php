<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\NessusClient;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncJobService;
use GlpiPlugin\Nessusglpi\TenableWasClient;

include('../../../inc/includes.php');

function nessusglpi_redirect_to_scan_list(): never
{
    global $CFG_GLPI;

    $target = rtrim((string) ($CFG_GLPI['root_doc'] ?? ''), '/') . '/plugins/nessusglpi/front/scan.php';
    header('Location: ' . $target);
    exit;
}

function nessusglpi_scan_name_from_details(array $details, string $scanId, string $scanType): string
{
    $candidates = [
        $details['info']['name'] ?? null,
        $details['name'] ?? null,
        $details['scan_name'] ?? null,
        $details['config_name'] ?? null,
        $details['application_name'] ?? null,
        $details['target'] ?? null,
        $details['url'] ?? null,
    ];

    foreach ($candidates as $candidate) {
        if (is_scalar($candidate) && trim((string) $candidate) !== '') {
            return trim((string) $candidate);
        }
    }

    return $scanType === Scan::SOURCE_WAS
        ? sprintf(__('WAS scan %s', 'nessusglpi'), $scanId)
        : sprintf(__('Scan %s', 'nessusglpi'), $scanId);
}

function nessusglpi_fetch_scan_details(string $scanType, string $scanId): array
{
    if ($scanType === Scan::SOURCE_WAS) {
        return (new TenableWasClient())->getScanDetails($scanId);
    }

    return (new NessusClient())->getScanDetails($scanId);
}

Session::checkRight(Scan::$rightname, READ);

$scan = new Scan();
$message = null;
$messageType = 'info';
$currentId = (int) ($_GET['id'] ?? ($_POST['id'] ?? 0));

if ($currentId > 0 && !Scan::canAccessScanId($currentId)) {
    Html::displayRightError();
}

if ($currentId <= 0 && strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'POST') {
    if (isset($_GET['scan_type'])) {
        $scan->fields['scan_type'] = Scan::normalizeSource($_GET['scan_type']);
    }

    if (isset($_GET['scan_id'])) {
        $scan->fields['scan_id'] = trim((string) $_GET['scan_id']);
    }
}

if (isset($_POST['add'])) {
    Session::checkRight(Scan::$rightname, CREATE);

    try {
        global $DB;

        $scanId = trim((string) ($_POST['scan_id'] ?? ''));
        if ($scanId === '') {
            throw new RuntimeException(__('Scan ID is required.', 'nessusglpi'));
        }

        $scanType = Scan::normalizeSource($_POST['scan_type'] ?? Scan::SOURCE_NESSUS);
        $encodedImportSeverities = Scan::encodeImportSeverities($_POST['import_severities'] ?? []);

        $scanDetails = nessusglpi_fetch_scan_details($scanType, $scanId);
        $scanName = nessusglpi_scan_name_from_details($scanDetails, $scanId, $scanType);

        $newId = $scan->add([
            'scan_id'           => $scanId,
            'scan_type'         => $scanType,
            'name'              => $scanName,
            'entities_id'       => (int) Session::getActiveEntity(),
            'import_severities' => $encodedImportSeverities,
        ]);

        if (!$newId) {
            throw new RuntimeException(__('Unable to create the scan record.', 'nessusglpi'));
        }

        $DB->update(Scan::getTable(), [
            'scan_type'         => $scanType,
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
        $scan->fields['scan_type'] = Scan::normalizeSource($_POST['scan_type'] ?? Scan::SOURCE_NESSUS);
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

        $scanType = Scan::normalizeSource($_POST['scan_type'] ?? Scan::SOURCE_NESSUS);
        $encodedImportSeverities = Scan::encodeImportSeverities($_POST['import_severities'] ?? []);

        $scanDetails = nessusglpi_fetch_scan_details($scanType, $scanId);
        $scanName = nessusglpi_scan_name_from_details($scanDetails, $scanId, $scanType);

        $scan->update([
            'id'                => $scanRecordId,
            'scan_id'           => $scanId,
            'scan_type'         => $scanType,
            'name'              => $scanName,
            'entities_id'       => (int) Session::getActiveEntity(),
            'import_severities' => $encodedImportSeverities,
        ]);

        $DB->update(Scan::getTable(), [
            'scan_id'           => $scanId,
            'scan_type'         => $scanType,
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
        $scan->fields['scan_type'] = Scan::normalizeSource($_POST['scan_type'] ?? Scan::SOURCE_NESSUS);
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
