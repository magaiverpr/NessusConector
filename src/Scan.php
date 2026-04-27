<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CommonDBTM;
use Dropdown;
use Html;
use Session;
use function array_filter;
use function array_map;
use function array_values;

class Scan extends CommonDBTM
{
    public static $table = 'glpi_plugin_nessusglpi_scans';

    public static $rightname = 'plugin_nessusglpi_scan';

    public static function getTable($classname = null)
    {
        return 'glpi_plugin_nessusglpi_scans';
    }

    public static function getTypeName($nb = 0): string
    {
        return __('Nessus scan', 'nessusglpi');
    }

    public static function canView(): bool
    {
        return Session::haveRight(static::$rightname, READ) > 0;
    }

    public static function canCreate(): bool
    {
        return Session::haveRight(static::$rightname, CREATE) > 0;
    }

    public static function canDelete(): bool
    {
        return Session::haveRight(static::$rightname, UPDATE) > 0;
    }

    public static function getSeverityOptions(): array
    {
        return [
            4 => 'Critical',
            3 => 'High',
            2 => 'Medium',
            1 => 'Low',
            0 => 'Info',
        ];
    }

    public static function normalizeImportSeverities($severities): array
    {
        if (is_string($severities)) {
            $trimmed = trim($severities);
            if ($trimmed !== '') {
                $decoded = json_decode($trimmed, true);
                if (is_array($decoded)) {
                    $severities = $decoded;
                } else {
                    $severities = array_map('trim', explode(',', $trimmed));
                }
            }
        }

        $values = array_map('intval', (array) $severities);
        $values = array_values(array_unique(array_filter($values, static fn (int $severity): bool => array_key_exists($severity, static::getSeverityOptions()))));
        rsort($values);

        if ($values === []) {
            return array_keys(static::getSeverityOptions());
        }

        return $values;
    }

    public static function encodeImportSeverities($severities): string
    {
        return json_encode(static::normalizeImportSeverities($severities), JSON_THROW_ON_ERROR);
    }

    public static function decodeImportSeverities($rawValue): array
    {
        if (is_array($rawValue)) {
            return static::normalizeImportSeverities($rawValue);
        }

        if (is_string($rawValue) && trim($rawValue) !== '') {
            $decoded = json_decode($rawValue, true);
            if (is_array($decoded)) {
                return static::normalizeImportSeverities($decoded);
            }
        }

        return array_keys(static::getSeverityOptions());
    }

    public static function getVisibleEntityIds(): array
    {
        $entities = [];

        if (method_exists(Session::class, 'getActiveEntities')) {
            $entities = array_map('intval', (array) Session::getActiveEntities());
        }

        if ($entities === [] && method_exists(Session::class, 'getActiveEntity')) {
            $activeEntity = (int) Session::getActiveEntity();
            if ($activeEntity > 0) {
                $entities[] = $activeEntity;
            }
        }

        return array_values(array_unique(array_filter($entities, static fn (int $id): bool => $id >= 0)));
    }

    public static function getVisibleScansCriteria(string $field = 'entities_id'): array
    {
        $entityIds = static::getVisibleEntityIds();
        if ($entityIds === []) {
            return ['id' => 0];
        }

        return [
            $field => $entityIds,
        ];
    }

    public static function canAccessScanId(int $scanId): bool
    {
        if ($scanId <= 0) {
            return false;
        }

        $scan = new self();
        if (!$scan->getFromDB($scanId)) {
            return false;
        }

        return in_array((int) ($scan->fields['entities_id'] ?? -1), static::getVisibleEntityIds(), true);
    }

    public static function deleteByIds(array $ids): int
    {
        global $DB;

        $visibleEntityIds = static::getVisibleEntityIds();
        $ids = array_values(array_filter(array_map('intval', $ids), static fn (int $id): bool => $id > 0));
        if ($ids === [] || $visibleEntityIds === []) {
            return 0;
        }

        $allowedIds = [];
        $allowedIterator = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => static::getTable(),
            'WHERE'  => [
                'id'          => $ids,
                'entities_id' => $visibleEntityIds,
            ],
        ]);

        foreach ($allowedIterator as $row) {
            $scanId = (int) ($row['id'] ?? 0);
            if ($scanId > 0) {
                $allowedIds[] = $scanId;
            }
        }

        $ids = array_values(array_unique($allowedIds));
        if ($ids === []) {
            return 0;
        }

        $hostIds = [];
        $hostIterator = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => Host::getTable(),
            'WHERE'  => [
                'plugin_nessusglpi_scans_id' => $ids,
            ],
        ]);

        foreach ($hostIterator as $row) {
            $hostId = (int) ($row['id'] ?? 0);
            if ($hostId > 0) {
                $hostIds[] = $hostId;
            }
        }

        $hostIds = array_values(array_unique($hostIds));

        $vulnerabilityIds = [];
        $vulnerabilityIterator = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => Vulnerability::getTable(),
            'WHERE'  => [
                'plugin_nessusglpi_scans_id' => $ids,
            ],
        ]);

        foreach ($vulnerabilityIterator as $row) {
            $vulnerabilityId = (int) ($row['id'] ?? 0);
            if ($vulnerabilityId > 0) {
                $vulnerabilityIds[] = $vulnerabilityId;
            }
        }

        $vulnerabilityIds = array_values(array_unique($vulnerabilityIds));

        if ($vulnerabilityIds !== []) {
            $DB->delete(VulnerabilityTicket::getTable(), [
                'plugin_nessusglpi_vulnerabilities_id' => $vulnerabilityIds,
            ]);
        }

        if ($hostIds !== []) {
            $DB->delete(HostTicket::getTable(), [
                'plugin_nessusglpi_hosts_id' => $hostIds,
            ]);
        }

        $DB->delete(Vulnerability::getTable(), [
            'plugin_nessusglpi_scans_id' => $ids,
        ]);
        $DB->delete(Host::getTable(), [
            'plugin_nessusglpi_scans_id' => $ids,
        ]);
        $DB->delete(ScanRun::getTable(), [
            'plugin_nessusglpi_scans_id' => $ids,
        ]);

        $deleted = 0;
        foreach ($ids as $id) {
            $scan = new self();
            if ($scan->delete(['id' => $id], true)) {
                $deleted++;
            }
        }

        return $deleted;
    }

    public static function getMenuName($nb = 0): string
    {
        return __('Nessus Conector', 'nessusglpi');
    }

    public static function getMenuContent(): array
    {
        $search = '/plugins/nessusglpi/front/scan.php';
        $form   = '/plugins/nessusglpi/front/scan.form.php';

        return [
            'title' => static::getMenuName(),
            'page'  => $search,
            'icon'  => 'ti ti-shield-search',
            'links' => [
                'search' => $search,
                'add'    => $form,
            ],
            'options' => [
                Scan::class => [
                    'title' => __('Scans', 'nessusglpi'),
                    'page'  => $search,
                    'links' => [
                        'search' => $search,
                        'add'    => $form,
                    ],
                ],
                Config::class => [
                    'title' => __('Configuration', 'nessusglpi'),
                    'page'  => '/plugins/nessusglpi/front/config.form.php',
                    'links' => [
                        'search' => '/plugins/nessusglpi/front/config.form.php',
                    ],
                ],
                Vulnerability::class => [
                    'title' => __('Vulnerabilities', 'nessusglpi'),
                    'page'  => '/plugins/nessusglpi/front/vulnerability.php',
                    'links' => [
                        'search' => '/plugins/nessusglpi/front/vulnerability.php',
                    ],
                ],
                ScanRun::class => [
                    'title' => __('Scan history', 'nessusglpi'),
                    'page'  => '/plugins/nessusglpi/front/scanrun.php',
                    'links' => [
                        'search' => '/plugins/nessusglpi/front/scanrun.php',
                    ],
                ],
            ],
        ];
    }

    public function defineTabs($options = []): array
    {
        $tabs = [];
        $this->addDefaultFormTab($tabs);
        $this->addStandardTab(ScanRun::class, $tabs, $options);
        return $tabs;
    }

    public function showForm($ID, array $options = []): bool
    {
        if (!self::canView()) {
            return false;
        }

        if (!$this->isNewID($ID)) {
            $this->getFromDB($ID);
        }

        $message = $options['message'] ?? null;
        $messageType = $options['message_type'] ?? 'info';
        $entityName = '-';
        $entityId = (int) ($this->fields['entities_id'] ?? Session::getActiveEntity());
        if ($entityId >= 0) {
            $entityName = Dropdown::getDropdownName('glpi_entities', $entityId);
            if ($entityName === '') {
                $entityName = (string) $entityId;
            }
        }
        $selectedSeverities = static::decodeImportSeverities($this->fields['import_severities'] ?? null);

        echo "<form method='post' action='" . static::getFormURL() . "'>";
        echo "<div class='card card-body'>";
        echo "<h2>" . __('Nessus scan', 'nessusglpi') . '</h2>';

        if (is_string($message) && $message !== '') {
            $class = $messageType === 'error' ? 'alert alert-danger' : 'alert alert-info';
            echo "<div class='${class}' role='alert'>" . Html::cleanInputText($message) . "</div>";
        }

        echo "<table class='tab_cadre_fixe'>";
        echo "<tr><th>" . __('Entity') . "</th><td>" . Html::cleanInputText((string) $entityName) . "</td></tr>";
        echo "<tr><th>" . __('Scan ID', 'nessusglpi') . "</th><td><input type='text' name='scan_id' value='" . Html::cleanInputText($this->fields['scan_id'] ?? '') . "' class='form-control'></td></tr>";
        echo "<tr><th>" . __('Imported severities', 'nessusglpi') . "</th><td>";
        foreach (static::getSeverityOptions() as $severity => $label) {
            $checked = in_array($severity, $selectedSeverities, true) ? ' checked' : '';
            echo "<label style='display:inline-flex; align-items:center; gap:6px; margin-right:16px; margin-bottom:6px;'>";
            echo "<input type='checkbox' name='import_severities[]' value='" . (int) $severity . "'" . $checked . ">";
            echo Html::cleanInputText($label);
            echo "</label>";
        }
        echo "<div style='margin-top:6px; color:#667085; font-size:12px;'>" . Html::cleanInputText(__('Choose which severities will be imported during synchronization.', 'nessusglpi')) . "</div>";
        echo "</td></tr>";

        if (!$this->isNewID($ID)) {
            echo "<tr><th>" . __('Name') . "</th><td>" . Html::cleanInputText($this->fields['name'] ?? '') . "</td></tr>";
        }

        echo '</table>';
        echo "<div class='mt-3'>";
        echo Html::hidden('id', ['value' => $this->fields['id'] ?? 0]);
        echo Html::hidden('entities_id', ['value' => $entityId]);
        echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);

        if ($this->isNewID($ID)) {
            echo Html::submit(_sx('button', 'Add'), ['name' => 'add']);
        } else {
            echo Html::submit(_sx('button', 'Save'), ['name' => 'update']);
        }

        echo '</div>';
        echo '</div>';
        Html::closeForm();

        return true;
    }

    public function prepareInputForAdd($input): array
    {
        $input['entities_id']       = (int) ($input['entities_id'] ?? Session::getActiveEntity());
        $input['import_severities'] = array_key_exists('import_severities', $input)
            ? static::encodeImportSeverities($input['import_severities'])
            : static::encodeImportSeverities($this->fields['import_severities'] ?? null);
        $input['is_active']         = 1;
        $input['date_creation']     = date('Y-m-d H:i:s');
        $input['date_mod']          = date('Y-m-d H:i:s');
        $input['comment']           = null;

        return $input;
    }

    public function prepareInputForUpdate($input): array
    {
        $input['entities_id']       = (int) ($input['entities_id'] ?? $this->fields['entities_id'] ?? Session::getActiveEntity());
        $input['import_severities'] = array_key_exists('import_severities', $input)
            ? static::encodeImportSeverities($input['import_severities'])
            : (string) ($this->fields['import_severities'] ?? static::encodeImportSeverities(null));
        $input['is_active']         = (int) ($input['is_active'] ?? $this->fields['is_active'] ?? 1);
        $input['date_mod']          = date('Y-m-d H:i:s');
        $input['comment']           = $input['comment'] ?? $this->fields['comment'] ?? null;

        return $input;
    }
}


