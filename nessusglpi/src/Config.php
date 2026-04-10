<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CommonDBTM;
use Html;
use RuntimeException;
use Session;

class Config extends CommonDBTM
{
    public static $table = 'glpi_plugin_nessusglpi_configs';

    public static $rightname = 'plugin_nessusglpi_config';

    public static function getTable($classname = null)
    {
        return 'glpi_plugin_nessusglpi_configs';
    }

    public static function getTypeName($nb = 0): string
    {
        return __('Nessus configuration', 'nessusglpi');
    }

    public static function canView(): bool
    {
        return Session::haveRight(static::$rightname, READ) > 0;
    }

    public static function canCreate(): bool
    {
        return Session::haveRight(static::$rightname, UPDATE) > 0;
    }

    public static function getSingleton(): self
    {
        global $DB;

        $config = new self();

        $row = $DB->request([
            'FROM'  => static::getTable(),
            'LIMIT' => 1,
        ])->current();

        if ($row && isset($row['id'])) {
            $config->getFromDB((int) $row['id']);
        }

        return $config;
    }

    public static function getAllowedItemtypes(): array
    {
        $config = static::getSingleton();
        $raw    = $config->fields['allowed_itemtypes'] ?? '[]';

        if (is_string($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        return [];
    }

    public static function getAvailableItemtypes(): array
    {
        return [
            'Computer'         => __('Computer'),
            'NetworkEquipment' => __('Network equipment'),
            'Printer'          => __('Printer'),
            'Phone'            => __('Phone'),
            'Unmanaged'        => __('Unmanaged device'),
        ];
    }

    public static function createFromInput(array $input): self
    {
        $config = new self();
        $config->fields = array_merge($config->fields, $config->normalizeInput($input));
        return $config;
    }

    public function showForm($ID, array $options = []): bool
    {
        if (!self::canView()) {
            return false;
        }

        if (!$this->isNewID($ID)) {
            $this->getFromDB($ID);
        }

        $allowed = $this->extractAllowedItemtypes($this->fields['allowed_itemtypes'] ?? '[]');
        $testResult = $options['test_result'] ?? null;

        echo "<form method='post' action='" . static::getFormURL() . "'>";
        echo "<div class='card card-body'>";
        echo "<h2>" . __('Nessus API configuration', 'nessusglpi') . '</h2>';

        if (is_array($testResult)) {
            $class = !empty($testResult['ok']) ? 'alert alert-success' : 'alert alert-danger';
            $message = Html::cleanInputText((string) ($testResult['message'] ?? ''));
            echo "<div class='${class}' role='alert'>${message}</div>";
        }

        echo "<table class='tab_cadre_fixe'>";
        echo "<tr><th>" . __('API URL', 'nessusglpi') . "</th><td><input type='text' name='api_url' value='" . Html::cleanInputText($this->fields['api_url'] ?? '') . "' class='form-control'></td></tr>";
        echo "<tr><th>" . __('Access key', 'nessusglpi') . "</th><td><input type='text' name='access_key' value='" . Html::cleanInputText($this->fields['access_key'] ?? '') . "' class='form-control'></td></tr>";
        echo "<tr><th>" . __('Secret key', 'nessusglpi') . "</th><td><input type='password' name='secret_key' value='" . Html::cleanInputText($this->fields['secret_key'] ?? '') . "' class='form-control'></td></tr>";
        echo "<tr><th>" . __('Timeout (seconds)', 'nessusglpi') . "</th><td><input type='number' min='1' name='timeout' value='" . (int) ($this->fields['timeout'] ?? 30) . "' class='form-control'></td></tr>";
        echo "<tr><th>" . __('Asset types for matching', 'nessusglpi') . '</th><td>';

        foreach (self::getAvailableItemtypes() as $type => $label) {
            $checked = in_array($type, $allowed, true) ? " checked" : '';
            echo "<label style='display:block'><input type='checkbox' name='allowed_itemtypes[]' value='" . Html::cleanInputText($type) . "'{$checked}> " . Html::cleanInputText($label) . '</label>';
        }

        echo '</td></tr>';
        echo '</table>';
        echo "<div class='mt-3 d-flex gap-2'>";
        echo Html::hidden('id', ['value' => $this->fields['id'] ?? 0]);
        echo Html::submit(_sx('button', 'Save'), ['name' => 'update']);
        echo Html::submit(__('Test connection', 'nessusglpi'), ['name' => 'test_connection']);
        echo '</div>';
        echo '</div>';
        Html::closeForm();

        return true;
    }

    public function prepareInputForAdd($input): array
    {
        return $this->normalizeInput($input);
    }

    public function prepareInputForUpdate($input): array
    {
        return $this->normalizeInput($input);
    }

    private function normalizeInput(array $input): array
    {
        $input['allowed_itemtypes'] = json_encode(array_values($input['allowed_itemtypes'] ?? []));
        $input['timeout']           = max(1, (int) ($input['timeout'] ?? 30));
        $input['date_mod']          = date('Y-m-d H:i:s');

        return $input;
    }

    private function extractAllowedItemtypes($raw): array
    {
        if (is_array($raw)) {
            return $raw;
        }

        if (is_string($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                return $decoded;
            }
        }

        return [];
    }
}
