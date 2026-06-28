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
        global $CFG_GLPI;

        if (!self::canView()) {
            return false;
        }

        if (!$this->isNewID($ID)) {
            $this->getFromDB($ID);
        }

        $canUpdate     = Session::haveRight(self::$rightname, UPDATE) > 0;
        $allowed       = $this->extractAllowedItemtypes($this->fields['allowed_itemtypes'] ?? '[]');
        $apiUrl        = (string) ($this->fields['api_url'] ?? '');
        $accessKey     = (string) ($this->fields['access_key'] ?? '');
        $secretKey     = (string) ($this->fields['secret_key'] ?? '');
        $wasApiUrl     = (string) ($this->fields['was_api_url'] ?? '');
        $wasAccessKey  = (string) ($this->fields['was_access_key'] ?? '');
        $wasSecretKey  = (string) ($this->fields['was_secret_key'] ?? '');
        $timeout       = (int) ($this->fields['timeout'] ?? 30);

        $hasWasFields  = array_key_exists('was_api_url', $this->fields);

        $assetsBase    = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
        $assetVersion  = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';
        $assetDir      = dirname(__DIR__) . '/public';
        // Append the file mtime so browsers fetch the new asset whenever it
        // changes, even between plugin releases (the plugin version alone does
        // not bust the cache during development/hotfixes).
        $cssVersion    = $assetVersion . '-' . (@filemtime($assetDir . '/css/config-form.css') ?: '0');
        $jsVersion     = $assetVersion . '-' . (@filemtime($assetDir . '/js/config-form.js') ?: '0');
        $ajaxUrl       = $assetsBase . '/ajax/config.test.php';

        $configState = [
            'ajaxUrl'        => $ajaxUrl,
            'csrf'           => Session::getNewCSRFToken(),
            'i18n'           => [
                'testing'           => __('Testing connection…', 'nessusglpi'),
                'success'           => __('Connection OK', 'nessusglpi'),
                'failed'            => __('Connection failed', 'nessusglpi'),
                'notTested'         => __('Not tested yet', 'nessusglpi'),
                'latency'           => __('%d ms', 'nessusglpi'),
                'invalidUrl'        => __('Enter a valid URL (https://host or http://host).', 'nessusglpi'),
                'urlPlaceholderVm'  => __('https://cloud.tenable.com', 'nessusglpi'),
                'urlPlaceholderWas' => __('https://cloud.tenable.com', 'nessusglpi'),
                'showSecret'        => __('Show secret', 'nessusglpi'),
                'hideSecret'        => __('Hide secret', 'nessusglpi'),
                'networkError'      => __('Network error. Please retry.', 'nessusglpi'),
            ],
        ];

        echo '<link rel="stylesheet" href="'
            . Html::cleanInputText($assetsBase . '/css/config-form.css?v=' . $cssVersion) . '">';

        echo '<div class="nessus-config-page" data-nessus-config="'
            . htmlspecialchars((string) json_encode($configState), ENT_QUOTES) . '">';

        echo '<div class="nessus-config-page__hero">';
        echo '<div class="nessus-config-page__title-group">';
        echo '<h2 class="nessus-config-page__title">'
            . Html::cleanInputText(__('Nessus connector configuration', 'nessusglpi')) . '</h2>';
        echo '<p class="nessus-config-page__subtitle">'
            . Html::cleanInputText(__('Connect to Tenable Nessus VM and Tenable WAS. Test each endpoint before saving.', 'nessusglpi'))
            . '</p>';
        echo '</div>';
        echo '</div>';

        echo '<form method="post" action="' . static::getFormURL() . '" class="nessus-config-form" novalidate>';

        echo '<div class="nessus-config-grid">';

        // -------- Card: Nessus VM ----------
        echo '<section class="nessus-config-card" data-nessus-config-card="nessus" data-provider="nessus">';
        echo '<header class="nessus-config-card__head">';
        echo '<div class="nessus-config-card__icon nessus-config-card__icon--vm">'
            . $this->renderInlineIcon('shield') . '</div>';
        echo '<div class="nessus-config-card__title-block">';
        echo '<h3 class="nessus-config-card__title">'
            . Html::cleanInputText(__('Nessus VM / Tenable VM', 'nessusglpi')) . '</h3>';
        echo '<p class="nessus-config-card__hint">'
            . Html::cleanInputText(__('REST API used to fetch scans, hosts and vulnerabilities.', 'nessusglpi'))
            . '</p>';
        echo '</div>';
        echo '<span class="nessus-conn-pill nessus-conn-pill--muted" data-nessus-conn-status>'
            . '<span class="nessus-conn-pill__dot"></span>'
            . '<span class="nessus-conn-pill__label">' . Html::cleanInputText(__('Not tested yet', 'nessusglpi')) . '</span>'
            . '<span class="nessus-conn-pill__latency" hidden></span>'
            . '</span>';
        echo '</header>';

        echo '<div class="nessus-config-card__body">';
        echo $this->renderTextField('api_url', __('API URL', 'nessusglpi'), $apiUrl, [
            'type'        => 'url',
            'placeholder' => 'https://cloud.tenable.com',
            'required'    => true,
            'data'        => ['nessus-config-input' => 'url'],
            'autocomplete'=> 'off',
        ]);
        echo $this->renderTextField('access_key', __('Access key', 'nessusglpi'), $accessKey, [
            'type'        => 'text',
            'placeholder' => '',
            'autocomplete'=> 'off',
            'spellcheck'  => 'false',
        ]);
        echo $this->renderSecretField('secret_key', __('Secret key', 'nessusglpi'), $secretKey);
        echo '<div class="nessus-conn-message" data-nessus-conn-message hidden></div>';
        echo '</div>';

        echo '<footer class="nessus-config-card__foot">';
        echo '<button type="button" class="nessus-config-btn nessus-config-btn--ghost"'
            . ' data-nessus-test-btn="nessus"' . ($canUpdate ? '' : ' disabled') . '>'
            . $this->renderInlineIcon('plug') . '<span>'
            . Html::cleanInputText(__('Test connection', 'nessusglpi')) . '</span></button>';
        echo '</footer>';
        echo '</section>';

        // -------- Card: Tenable WAS ----------
        echo '<section class="nessus-config-card" data-nessus-config-card="was" data-provider="was">';
        echo '<header class="nessus-config-card__head">';
        echo '<div class="nessus-config-card__icon nessus-config-card__icon--was">'
            . $this->renderInlineIcon('globe') . '</div>';
        echo '<div class="nessus-config-card__title-block">';
        echo '<h3 class="nessus-config-card__title">'
            . Html::cleanInputText(__('Tenable WAS (Web App Scanning)', 'nessusglpi')) . '</h3>';
        echo '<p class="nessus-config-card__hint">';
        if ($hasWasFields) {
            echo Html::cleanInputText(__('Dedicated credentials. Leave blank to reuse the Nessus VM keys.', 'nessusglpi'));
        } else {
            echo Html::cleanInputText(__('Currently sharing the Nessus VM credentials. WAS-specific fields are not enabled in this build.', 'nessusglpi'));
        }
        echo '</p>';
        echo '</div>';
        echo '<span class="nessus-conn-pill nessus-conn-pill--muted" data-nessus-conn-status>'
            . '<span class="nessus-conn-pill__dot"></span>'
            . '<span class="nessus-conn-pill__label">' . Html::cleanInputText(__('Not tested yet', 'nessusglpi')) . '</span>'
            . '<span class="nessus-conn-pill__latency" hidden></span>'
            . '</span>';
        echo '</header>';

        echo '<div class="nessus-config-card__body">';
        if ($hasWasFields) {
            echo $this->renderTextField('was_api_url', __('WAS API URL', 'nessusglpi'), $wasApiUrl, [
                'type'        => 'url',
                'placeholder' => 'https://cloud.tenable.com',
                'data'        => ['nessus-config-input' => 'url'],
                'autocomplete'=> 'off',
            ]);
            echo $this->renderTextField('was_access_key', __('WAS access key', 'nessusglpi'), $wasAccessKey, [
                'type'        => 'text',
                'placeholder' => '',
                'autocomplete'=> 'off',
                'spellcheck'  => 'false',
            ]);
            echo $this->renderSecretField('was_secret_key', __('WAS secret key', 'nessusglpi'), $wasSecretKey);
        } else {
            echo '<div class="nessus-config-empty-note">'
                . $this->renderInlineIcon('info')
                . '<span>' . Html::cleanInputText(__('WAS uses the same keys configured above. Test below to verify access.', 'nessusglpi')) . '</span>'
                . '</div>';
        }
        echo '<div class="nessus-conn-message" data-nessus-conn-message hidden></div>';
        echo '</div>';

        echo '<footer class="nessus-config-card__foot">';
        echo '<button type="button" class="nessus-config-btn nessus-config-btn--ghost"'
            . ' data-nessus-test-btn="was"' . ($canUpdate ? '' : ' disabled') . '>'
            . $this->renderInlineIcon('plug') . '<span>'
            . Html::cleanInputText(__('Test connection', 'nessusglpi')) . '</span></button>';
        echo '</footer>';
        echo '</section>';

        echo '</div>'; // /grid

        // -------- Card: Asset matching + timeout ----------
        echo '<section class="nessus-config-card nessus-config-card--wide">';
        echo '<header class="nessus-config-card__head">';
        echo '<div class="nessus-config-card__icon nessus-config-card__icon--asset">'
            . $this->renderInlineIcon('target') . '</div>';
        echo '<div class="nessus-config-card__title-block">';
        echo '<h3 class="nessus-config-card__title">'
            . Html::cleanInputText(__('Asset matching & request settings', 'nessusglpi')) . '</h3>';
        echo '<p class="nessus-config-card__hint">'
            . Html::cleanInputText(__('Choose which GLPI itemtypes the importer will try to match against.', 'nessusglpi'))
            . '</p>';
        echo '</div>';
        echo '</header>';

        echo '<div class="nessus-config-card__body nessus-config-card__body--split">';

        echo '<div class="nessus-config-itemtypes">';
        echo '<span class="nessus-config-field-label">'
            . Html::cleanInputText(__('Asset types for matching', 'nessusglpi')) . '</span>';
        echo '<div class="nessus-config-itemtypes__grid">';
        foreach (self::getAvailableItemtypes() as $type => $label) {
            $checked = in_array($type, $allowed, true) ? ' checked' : '';
            echo '<label class="nessus-config-checkbox">';
            echo '<input type="checkbox" name="allowed_itemtypes[]" value="'
                . Html::cleanInputText($type) . '"' . $checked . '>';
            echo '<span class="nessus-config-checkbox__indicator"></span>';
            echo '<span class="nessus-config-checkbox__label">' . Html::cleanInputText($label) . '</span>';
            echo '</label>';
        }
        echo '</div>';
        echo '</div>';

        echo '<div class="nessus-config-timeout">';
        echo $this->renderTextField('timeout', __('HTTP timeout (seconds)', 'nessusglpi'), (string) $timeout, [
            'type'        => 'number',
            'min'         => '1',
            'max'         => '600',
            'placeholder' => '30',
            'hint'        => __('Applied to both Nessus VM and Tenable WAS HTTP requests.', 'nessusglpi'),
        ]);
        echo '</div>';

        echo '</div>'; // /body split
        echo '</section>';

        echo '<div class="nessus-config-actions">';
        echo Html::hidden('id', ['value' => $this->fields['id'] ?? 0]);
        if ($canUpdate) {
            echo '<button type="submit" name="update" value="1" class="nessus-config-btn nessus-config-btn--primary">'
                . $this->renderInlineIcon('save') . '<span>'
                . Html::cleanInputText(_sx('button', 'Save')) . '</span></button>';
        } else {
            echo '<p class="nessus-config-readonly">'
                . Html::cleanInputText(__('You have read-only access to the configuration.', 'nessusglpi'))
                . '</p>';
        }
        echo '</div>';

        Html::closeForm();
        echo '</div>'; // /page

        echo '<script src="' . Html::cleanInputText($assetsBase . '/js/config-form.js?v=' . $jsVersion) . '" defer></script>';

        return true;
    }

    public function prepareInputForAdd($input): array
    {
        return $this->normalizeInput($input);
    }

    public function prepareInputForUpdate($input): array
    {
        foreach (['secret_key', 'was_secret_key'] as $field) {
            if (isset($input[$field]) && trim((string) $input[$field]) === '') {
                unset($input[$field]);
            }
        }
        return $this->normalizeInput($input);
    }

    private function normalizeInput(array $input): array
    {
        $input['allowed_itemtypes'] = json_encode(array_values($input['allowed_itemtypes'] ?? []));
        $input['timeout']           = max(1, (int) ($input['timeout'] ?? 30));
        $input['date_mod']          = date('Y-m-d H:i:s');

        // Secret keys are stored as-is (plaintext, like access_key). The previous
        // GLPIKey encryption made saving fragile (length overflow / key-read
        // failures), so we keep the simpler legacy behaviour for reliability.

        return $input;
    }

    public function getSecretKey(): string
    {
        return self::decryptSecret($this->fields['secret_key'] ?? '');
    }

    public function getWasSecretKey(): string
    {
        return self::decryptSecret($this->fields['was_secret_key'] ?? '');
    }

    public static function decryptSecret($stored): string
    {
        // Secrets are stored as plaintext (old method), so this is a passthrough.
        // We deliberately do NOT call GLPIKey::decrypt() here: it emits a PHP
        // warning ("Unable to extract nonce from string") on plaintext values,
        // and with GLPI debug mode on that warning is injected into AJAX
        // responses and breaks JSON parsing in the connection test.
        return (string) $stored;
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

    private function renderTextField(string $name, string $label, string $value, array $opts = []): string
    {
        $type        = (string) ($opts['type'] ?? 'text');
        $placeholder = (string) ($opts['placeholder'] ?? '');
        $required    = !empty($opts['required']);
        $hint        = (string) ($opts['hint'] ?? '');
        $autocomplete= (string) ($opts['autocomplete'] ?? 'on');
        $spellcheck  = (string) ($opts['spellcheck'] ?? 'true');
        $min         = $opts['min'] ?? null;
        $max         = $opts['max'] ?? null;
        $dataAttrs   = '';

        if (!empty($opts['data']) && is_array($opts['data'])) {
            foreach ($opts['data'] as $k => $v) {
                $dataAttrs .= ' data-' . Html::cleanInputText($k) . '="' . Html::cleanInputText((string) $v) . '"';
            }
        }

        $out  = '<div class="nessus-config-field" data-nessus-config-field="' . Html::cleanInputText($name) . '">';
        $out .= '<label class="nessus-config-field-label" for="nessus-config-' . Html::cleanInputText($name) . '">'
              . Html::cleanInputText($label)
              . ($required ? ' <span class="nessus-config-field-required" aria-hidden="true">*</span>' : '')
              . '</label>';
        $out .= '<input class="nessus-config-input" id="nessus-config-' . Html::cleanInputText($name) . '"'
             . ' type="' . Html::cleanInputText($type) . '"'
             . ' name="' . Html::cleanInputText($name) . '"'
             . ' value="' . Html::cleanInputText($value) . '"'
             . ($placeholder !== '' ? ' placeholder="' . Html::cleanInputText($placeholder) . '"' : '')
             . ($required ? ' required' : '')
             . ($min !== null ? ' min="' . Html::cleanInputText((string) $min) . '"' : '')
             . ($max !== null ? ' max="' . Html::cleanInputText((string) $max) . '"' : '')
             . ' autocomplete="' . Html::cleanInputText($autocomplete) . '"'
             . ' spellcheck="' . Html::cleanInputText($spellcheck) . '"'
             . $dataAttrs
             . '>';
        $out .= '<div class="nessus-config-field-feedback" data-nessus-field-feedback hidden></div>';
        if ($hint !== '') {
            $out .= '<p class="nessus-config-field-hint">' . Html::cleanInputText($hint) . '</p>';
        }
        $out .= '</div>';

        return $out;
    }

    private function renderSecretField(string $name, string $label, string $value): string
    {
        $out  = '<div class="nessus-config-field" data-nessus-config-field="' . Html::cleanInputText($name) . '">';
        $out .= '<label class="nessus-config-field-label" for="nessus-config-' . Html::cleanInputText($name) . '">'
              . Html::cleanInputText($label) . '</label>';
        $out .= '<div class="nessus-config-secret">';
        $out .= '<input class="nessus-config-input nessus-config-input--secret"'
             . ' id="nessus-config-' . Html::cleanInputText($name) . '"'
             . ' type="password" name="' . Html::cleanInputText($name) . '"'
             . ' value=""'
             . ($value !== '' ? ' placeholder="' . Html::cleanInputText(__('Leave blank to keep current value', 'nessusglpi')) . '"' : '')
             . ' autocomplete="new-password" spellcheck="false"'
             . ' data-nessus-secret-input>';
        $out .= '<button type="button" class="nessus-config-secret__toggle"'
             . ' data-nessus-secret-toggle'
             . ' aria-label="' . Html::cleanInputText(__('Toggle secret visibility', 'nessusglpi')) . '">'
             . $this->renderInlineIcon('eye')
             . $this->renderInlineIcon('eye-off')
             . '</button>';
        $out .= '</div>';
        $out .= '</div>';

        return $out;
    }

    private function renderInlineIcon(string $name): string
    {
        $icons = [
            'shield' => '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
            'globe'  => '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 010 20"/><path d="M12 2a15.3 15.3 0 000 20"/></svg>',
            'target' => '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>',
            'plug'   => '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22v-5"/><path d="M9 7V2"/><path d="M15 7V2"/><path d="M6 13V8a1 1 0 011-1h10a1 1 0 011 1v5a5 5 0 11-10 0z"/></svg>',
            'save'   => '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 01-2-2V5a2 2 0 012-2h11l5 5v11a2 2 0 01-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>',
            'eye'    => '<svg class="nessus-config-secret__icon nessus-config-secret__icon--show" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
            'eye-off'=> '<svg class="nessus-config-secret__icon nessus-config-secret__icon--hide" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.94 10.94 0 0112 20c-7 0-11-8-11-8a19.77 19.77 0 014.22-5.94"/><path d="M9.9 4.24A10.94 10.94 0 0112 4c7 0 11 8 11 8a19.86 19.86 0 01-3.17 4.19"/><path d="M14.12 14.12a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>',
            'info'   => '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
        ];

        return $icons[$name] ?? '';
    }
}
