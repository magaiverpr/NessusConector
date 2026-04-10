<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\NessusClient;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncService;

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

if (isset($_POST['add'])) {
    Session::checkRight(Scan::$rightname, CREATE);

    try {
        $scanId = trim((string) ($_POST['scan_id'] ?? ''));
        if ($scanId === '') {
            throw new RuntimeException(__('Scan ID is required.', 'nessusglpi'));
        }

        $scanDetails = (new NessusClient())->getScanDetails($scanId);
        $scanName = trim((string) ($scanDetails['info']['name'] ?? $scanDetails['name'] ?? ''));
        if ($scanName === '') {
            $scanName = sprintf(__('Scan %s', 'nessusglpi'), $scanId);
        }

        $newId = $scan->add([
            'scan_id' => $scanId,
            'name'    => $scanName,
        ]);

        if (!$newId) {
            throw new RuntimeException(__('Unable to create the scan record.', 'nessusglpi'));
        }

        try {
            (new SyncService())->runScan((int) $newId);
            Session::addMessageAfterRedirect(__('Scan created and initial synchronization completed successfully.', 'nessusglpi'));
        } catch (Throwable $syncException) {
            Session::addMessageAfterRedirect(
                sprintf(
                    __('Scan created successfully, but the initial synchronization failed: %s', 'nessusglpi'),
                    $syncException->getMessage()
                ),
                true
            );
        }

        nessusglpi_redirect_to_scan_list();
    } catch (Throwable $e) {
        $message = $e->getMessage();
        $messageType = 'error';
        $scan->fields['scan_id'] = (string) ($_POST['scan_id'] ?? '');
    }
}

if (isset($_POST['update'])) {
    Session::checkRight(Scan::$rightname, UPDATE);

    try {
        $scanId = trim((string) ($_POST['scan_id'] ?? ''));
        if ($scanId === '') {
            throw new RuntimeException(__('Scan ID is required.', 'nessusglpi'));
        }

        $scanDetails = (new NessusClient())->getScanDetails($scanId);
        $scanName = trim((string) ($scanDetails['info']['name'] ?? $scanDetails['name'] ?? ''));
        if ($scanName === '') {
            $scanName = sprintf(__('Scan %s', 'nessusglpi'), $scanId);
        }

        $scan->update([
            'id'      => (int) ($_POST['id'] ?? 0),
            'scan_id' => $scanId,
            'name'    => $scanName,
        ]);

        Session::addMessageAfterRedirect(__('Scan updated successfully.', 'nessusglpi'));
        nessusglpi_redirect_to_scan_list();
    } catch (Throwable $e) {
        $message = $e->getMessage();
        $messageType = 'error';
        $scan->fields['id'] = (int) ($_POST['id'] ?? 0);
        $scan->fields['scan_id'] = (string) ($_POST['scan_id'] ?? '');
    }
}

Html::header(__('Nessus scan', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');
$scan->showForm((int) ($_GET['id'] ?? ($_POST['id'] ?? 0)), [
    'message'      => $message,
    'message_type' => $messageType,
]);
Html::footer();
