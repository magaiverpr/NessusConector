<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Config;
use GlpiPlugin\Nessusglpi\Scan;
use GlpiPlugin\Nessusglpi\SyncService;

include('../../../inc/includes.php');

Session::checkRight(Scan::$rightname, READ);

$syncResult = null;
$deleteResult = null;

if (isset($_POST['delete_selected_scans'])) {
    Session::checkRight(Scan::$rightname, UPDATE);

    $selectedIds = array_map('intval', (array) ($_POST['scan_ids'] ?? []));
    $selectedIds = array_values(array_filter($selectedIds, static fn (int $id): bool => $id > 0));

    if ($selectedIds === []) {
        $deleteResult = [
            'ok'      => false,
            'message' => __('Select at least one scan to delete.', 'nessusglpi'),
        ];
    } else {
        $deleted = Scan::deleteByIds($selectedIds);
        $deleteResult = [
            'ok'      => true,
            'message' => sprintf(__('Deleted %d scan(s).', 'nessusglpi'), $deleted),
        ];
    }
}

if (isset($_POST['sync_scan'])) {
    Session::checkRight(Scan::$rightname, UPDATE);

    $scanId = (int) ($_POST['id'] ?? 0);
    if (!Scan::canAccessScanId($scanId)) {
        Html::displayRightError();
    }

    try {
        $runId = (new SyncService())->runScan($scanId);
        $syncResult = [
            'ok'      => true,
            'message' => sprintf(__('Synchronization completed. Run #%d created.', 'nessusglpi'), $runId),
        ];
    } catch (Throwable $e) {
        $syncResult = [
            'ok'      => false,
            'message' => $e->getMessage(),
        ];
    }
}

Html::header(__('Nessus scans', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

global $DB;

$config = Config::getSingleton();
$nessusBaseUrl = rtrim((string) ($config->fields['api_url'] ?? ''), '/');
$entityCriteria = Scan::getVisibleScansCriteria();

echo "<div class='card card-body'>";
echo "<h2>" . __('Nessus scans', 'nessusglpi') . "</h2>";

if (is_array($syncResult)) {
    $class = !empty($syncResult['ok']) ? 'alert alert-success' : 'alert alert-danger';
    echo "<div class='${class}' role='alert'>" . htmlspecialchars((string) $syncResult['message'], ENT_QUOTES) . "</div>";
}

if (is_array($deleteResult)) {
    $class = !empty($deleteResult['ok']) ? 'alert alert-success' : 'alert alert-danger';
    echo "<div class='${class}' role='alert'>" . htmlspecialchars((string) $deleteResult['message'], ENT_QUOTES) . "</div>";
}

$bulkFormId = 'nessusglpi-delete-scans-form';
$deleteConfirm = addslashes(__('Are you sure you want to delete the selected scans and all plugin data related to them?', 'nessusglpi'));
$syncConfirm = addslashes(__('Do you want to synchronize this scan now?', 'nessusglpi'));
echo "<p><a class='btn btn-primary' href='scan.form.php'>" . __('Add') . "</a></p>";
echo "<form id='" . $bulkFormId . "' method='post' action=''>";
echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
echo "</form>";
echo "<div style='margin-bottom: 12px;'>";
echo '<button type="submit" form="' . $bulkFormId . '" name="delete_selected_scans" value="1" class="btn btn-outline-danger" onclick="return confirm(\'' . $deleteConfirm . '\');">' . Html::cleanInputText(__('Delete selected', 'nessusglpi')) . '</button>';
echo "</div>";
echo "<table class='tab_cadre_fixehov'>";
echo "<tr><th><input type='checkbox' onclick=\"document.querySelectorAll('input[name=\'scan_ids[]\']').forEach(cb => cb.checked = this.checked);\"></th><th>ID</th><th>" . __('Entity') . "</th><th>" . __('Name') . "</th><th>" . __('Scan ID', 'nessusglpi') . "</th><th>" . __('Scan executed at', 'nessusglpi') . "</th><th>" . __('Last synchronization', 'nessusglpi') . "</th><th>" . __('Status') . "</th><th>" . __('Actions') . "</th></tr>";

foreach ($DB->request([
    'FROM'  => 'glpi_plugin_nessusglpi_scans',
    'WHERE' => $entityCriteria,
    'ORDER' => ['id DESC'],
]) as $row) {
    echo "<tr>";
    echo "<td><input type='checkbox' name='scan_ids[]' value='" . (int) $row['id'] . "' form='" . $bulkFormId . "'></td>";
    echo "<td>" . (int) $row['id'] . "</td>";
    echo "<td>" . Html::cleanInputText(Dropdown::getDropdownName('glpi_entities', (int) ($row['entities_id'] ?? 0))) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['name'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['scan_id'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['last_scan_at'] ?? '-'), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['last_sync_at'] ?? '-'), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['last_sync_status'] ?? '-'), ENT_QUOTES) . "</td>";
    echo "<td style='white-space:nowrap;'>";
    echo "<a href='scan.form.php?id=" . (int) $row['id'] . "'>" . __('Edit') . "</a>";
    echo " <a class='btn btn-sm btn-outline-secondary' href='scan.vulnerabilities.php?scan_id=" . (int) $row['id'] . "'>" . __('View vulnerabilities', 'nessusglpi') . "</a>";
    if ($nessusBaseUrl !== '' && (string) ($row['last_sync_status'] ?? '') === 'success') {
        $nessusUrl = $nessusBaseUrl . '/#/scans/reports/' . rawurlencode((string) ($row['scan_id'] ?? '')) . '/scan-summary';
        echo " <a class='btn btn-sm btn-outline-dark' target='_blank' rel='noopener noreferrer' href='" . htmlspecialchars($nessusUrl, ENT_QUOTES) . "'>" . __('Open in Nessus', 'nessusglpi') . "</a>";
    }
    echo "<form method='post' action='' style='display:inline-block; margin-left: 8px;'>";
    echo Html::hidden('id', ['value' => (int) $row['id']]);
    echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
    echo Html::submit(__('Sync', 'nessusglpi'), ['name' => 'sync_scan', 'class' => 'btn btn-sm btn-outline-primary', 'onclick' => "return confirm('" . $syncConfirm . "');"]);
    echo "</form>";
    echo "</td>";
    echo "</tr>";
}

echo "</table>";
echo "</div>";
Html::footer();
