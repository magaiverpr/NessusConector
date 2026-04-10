<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CommonDBTM;
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

    public static function deleteByIds(array $ids): int
    {
        global $DB;

        $ids = array_values(array_filter(array_map('intval', $ids), static fn (int $id): bool => $id > 0));
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

        echo "<form method='post' action='" . static::getFormURL() . "'>";
        echo "<div class='card card-body'>";
        echo "<h2>" . __('Nessus scan', 'nessusglpi') . '</h2>';

        if (is_string($message) && $message !== '') {
            $class = $messageType === 'error' ? 'alert alert-danger' : 'alert alert-info';
            echo "<div class='${class}' role='alert'>" . Html::cleanInputText($message) . "</div>";
        }

        echo "<table class='tab_cadre_fixe'>";
        echo "<tr><th>" . __('Scan ID', 'nessusglpi') . "</th><td><input type='text' name='scan_id' value='" . Html::cleanInputText($this->fields['scan_id'] ?? '') . "' class='form-control'></td></tr>";

        if (!$this->isNewID($ID)) {
            echo "<tr><th>" . __('Name') . "</th><td>" . Html::cleanInputText($this->fields['name'] ?? '') . "</td></tr>";
        }

        echo '</table>';
        echo "<div class='mt-3'>";
        echo Html::hidden('id', ['value' => $this->fields['id'] ?? 0]);
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
        $input['is_active']     = 1;
        $input['date_creation'] = date('Y-m-d H:i:s');
        $input['date_mod']      = date('Y-m-d H:i:s');
        $input['comment']       = null;

        return $input;
    }

    public function prepareInputForUpdate($input): array
    {
        $input['is_active'] = (int) ($this->fields['is_active'] ?? 1);
        $input['date_mod']  = date('Y-m-d H:i:s');
        $input['comment']   = $this->fields['comment'] ?? null;

        return $input;
    }
}
