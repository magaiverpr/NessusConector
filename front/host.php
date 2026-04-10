<?php

declare(strict_types=1);

use GlpiPlugin\Nessusglpi\Host;

include('../../../inc/includes.php');

Session::checkRight(Host::$rightname, READ);

$deleteResult = null;

if (isset($_POST['delete_selected_hosts'])) {
    Session::checkRight(Host::$rightname, UPDATE);

    $selectedIds = array_map('intval', (array) ($_POST['host_ids'] ?? []));
    $selectedIds = array_values(array_filter($selectedIds, static fn (int $id): bool => $id > 0));

    if ($selectedIds === []) {
        $deleteResult = [
            'ok'      => false,
            'message' => __('Select at least one imported host to delete.', 'nessusglpi'),
        ];
    } else {
        $deleted = Host::deleteByIds($selectedIds);
        $deleteResult = [
            'ok'      => true,
            'message' => sprintf(__('Deleted %d imported host(s).', 'nessusglpi'), $deleted),
        ];
    }
}

Html::header(__('Imported hosts', 'nessusglpi'), $_SERVER['PHP_SELF'], 'plugins', 'GlpiPlugin\\Nessusglpi\\Scan');

global $DB;

echo "<div class='card card-body'>";
echo "<h2>" . __('Imported hosts', 'nessusglpi') . "</h2>";

if (is_array($deleteResult)) {
    $class = !empty($deleteResult['ok']) ? 'alert alert-success' : 'alert alert-danger';
    echo "<div class='${class}' role='alert'>" . htmlspecialchars((string) $deleteResult['message'], ENT_QUOTES) . "</div>";
}

echo "<form method='post' action=''>";
echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);
echo "<div style='margin-bottom: 12px;'>";
echo Html::submit(__('Delete selected', 'nessusglpi'), ['name' => 'delete_selected_hosts', 'class' => 'btn btn-outline-danger']);
echo "</div>";
echo "<table class='tab_cadre_fixehov'>";
echo "<tr><th><input type='checkbox' onclick=\"document.querySelectorAll('input[name=\'host_ids[]\']').forEach(cb => cb.checked = this.checked);\"></th><th>ID</th><th>" . __('Hostname', 'nessusglpi') . "</th><th>FQDN</th><th>IP</th><th>" . __('Match status', 'nessusglpi') . "</th><th>" . __('Linked asset', 'nessusglpi') . "</th></tr>";

foreach ($DB->request([
    'FROM'  => Host::getTable(),
    'ORDER' => ['id DESC'],
]) as $row) {
    $linkedAsset = '-';

    if (!empty($row['itemtype']) && (int) ($row['items_id'] ?? 0) > 0) {
        $item = getItemForItemtype((string) $row['itemtype']);
        if ($item instanceof CommonDBTM && $item->getFromDB((int) $row['items_id'])) {
            $itemName = method_exists($item, 'getName') ? $item->getName() : ($item->fields['name'] ?? ((string) $row['itemtype'] . ' #' . (int) $row['items_id']));
            $linkedAsset = '<a href="' . htmlspecialchars($item->getLinkURL(), ENT_QUOTES) . '">' . htmlspecialchars((string) $itemName, ENT_QUOTES) . '</a>';
        } else {
            $linkedAsset = htmlspecialchars((string) $row['itemtype'], ENT_QUOTES) . ' #' . (int) $row['items_id'];
        }
    }

    echo "<tr>";
    echo "<td><input type='checkbox' name='host_ids[]' value='" . (int) $row['id'] . "'></td>";
    echo "<td>" . (int) $row['id'] . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['hostname'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['fqdn'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['ip'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . htmlspecialchars((string) ($row['match_status'] ?? ''), ENT_QUOTES) . "</td>";
    echo "<td>" . $linkedAsset . "</td>";
    echo "</tr>";
}

echo "</table>";
echo "</form>";
echo "</div>";
Html::footer();
