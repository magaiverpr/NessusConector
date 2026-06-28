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
    public const SOURCE_NESSUS = 'nessus';
    public const SOURCE_WAS = 'was';

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

    public static function getSourceOptions(): array
    {
        return [
            self::SOURCE_NESSUS => __('Nessus / Tenable VM', 'nessusglpi'),
            self::SOURCE_WAS    => __('Tenable WAS', 'nessusglpi'),
        ];
    }

    public static function normalizeSource($source): string
    {
        $source = strtolower(trim((string) $source));

        return array_key_exists($source, self::getSourceOptions())
            ? $source
            : self::SOURCE_NESSUS;
    }

    public static function getSourceLabel($source): string
    {
        $source = self::normalizeSource($source);
        $options = self::getSourceOptions();

        return (string) ($options[$source] ?? $source);
    }

    public static function statusBucket(string $status): string
    {
        $value = strtolower(trim($status));
        if ($value === '' || $value === '-') {
            return 'unknown';
        }

        $buckets = [
            'success' => ['success', 'completed', 'imported', 'done', 'ok'],
            'running' => ['running', 'processing', 'pending', 'queued', 'in_progress'],
            'warning' => ['stopped', 'canceled', 'cancelled', 'paused', 'partial', 'skipped'],
            'danger'  => ['failed', 'error', 'aborted', 'crashed'],
            'muted'   => ['empty', 'never', 'no_data'],
        ];

        foreach ($buckets as $bucket => $values) {
            if (in_array($value, $values, true)) {
                return $bucket;
            }
        }

        return 'unknown';
    }

    public static function statusLabel(string $status): string
    {
        $clean = trim($status);
        if ($clean === '') {
            return __('Never synced', 'nessusglpi');
        }

        return ucwords(str_replace(['_', '-'], ' ', strtolower($clean)));
    }

    public static function relativeDate(string $value): string
    {
        if ($value === '' || $value === '-') {
            return '';
        }

        $timestamp = is_numeric($value) ? (int) $value : strtotime($value);
        if (!is_int($timestamp) || $timestamp <= 0) {
            return '';
        }

        $diff = max(0, time() - $timestamp);
        if ($diff < 60) {
            return __('just now', 'nessusglpi');
        }
        if ($diff < 3600) {
            $minutes = (int) floor($diff / 60);
            return sprintf(_n('%d minute ago', '%d minutes ago', $minutes, 'nessusglpi'), $minutes);
        }
        if ($diff < 86400) {
            $hours = (int) floor($diff / 3600);
            return sprintf(_n('%d hour ago', '%d hours ago', $hours, 'nessusglpi'), $hours);
        }
        if ($diff < 2592000) {
            $days = (int) floor($diff / 86400);
            return sprintf(_n('%d day ago', '%d days ago', $days, 'nessusglpi'), $days);
        }
        if ($diff < 31536000) {
            $months = (int) floor($diff / 2592000);
            return sprintf(_n('%d month ago', '%d months ago', $months, 'nessusglpi'), $months);
        }
        $years = (int) floor($diff / 31536000);
        return sprintf(_n('%d year ago', '%d years ago', $years, 'nessusglpi'), $years);
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
        if (!self::canView()) {
            return [];
        }

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
                'trends' => [
                    'title' => __('Trends', 'nessusglpi'),
                    'page'  => '/plugins/nessusglpi/front/trends.php',
                    'icon'  => 'ti ti-chart-arrows-vertical',
                    'links' => [
                        'search' => '/plugins/nessusglpi/front/trends.php',
                    ],
                ],
                'coverage' => [
                    'title' => __('Coverage (VMs without Nessus)', 'nessusglpi'),
                    'page'  => '/plugins/nessusglpi/front/coverage.php',
                    'links' => [
                        'search' => '/plugins/nessusglpi/front/coverage.php',
                    ],
                ],
                ScanRun::class => [
                    'title' => __('Scan history', 'nessusglpi'),
                    'page'  => '/plugins/nessusglpi/front/scanrun.php',
                    'links' => [
                        'search' => '/plugins/nessusglpi/front/scanrun.php',
                    ],
                ],
                'activity_log' => [
                    'title' => __('Activity log', 'nessusglpi'),
                    'page'  => '/plugins/nessusglpi/front/log.php',
                    'links' => [
                        'search' => '/plugins/nessusglpi/front/log.php',
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
        global $CFG_GLPI;

        if (!self::canView()) {
            return false;
        }

        if (!$this->isNewID($ID)) {
            $this->getFromDB($ID);
        }

        $isNew         = $this->isNewID($ID);
        $message       = $options['message'] ?? null;
        $messageType   = $options['message_type'] ?? 'info';
        $entityId      = (int) ($this->fields['entities_id'] ?? Session::getActiveEntity());
        $entityName    = '-';
        if ($entityId >= 0) {
            $entityName = Dropdown::getDropdownName('glpi_entities', $entityId);
            if ($entityName === '') {
                $entityName = (string) $entityId;
            }
        }
        $selectedSeverities = static::decodeImportSeverities($this->fields['import_severities'] ?? null);
        $selectedSource     = static::normalizeSource($this->fields['scan_type'] ?? self::SOURCE_NESSUS);
        $scanIdValue        = (string) ($this->fields['scan_id'] ?? '');
        $scanName           = (string) ($this->fields['name'] ?? '');
        $canUpdate          = Session::haveRight(self::$rightname, $isNew ? CREATE : UPDATE) > 0;

        $assetsBase   = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
        $assetVersion = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';
        $previewUrl   = $assetsBase . '/ajax/scan.preview.php';

        $jsState = [
            'previewUrl'  => $previewUrl,
            'csrf'        => Session::getNewCSRFToken(),
            'isNew'       => $isNew,
            'placeholders' => [
                self::SOURCE_NESSUS => __('Numeric scan ID, e.g. 42', 'nessusglpi'),
                self::SOURCE_WAS    => __('UUID, e.g. 1a2b3c4d-1234-5678-9abc-def012345678', 'nessusglpi'),
            ],
            'hints'       => [
                self::SOURCE_NESSUS => __('Find the numeric scan ID in the Tenable VM URL (/scans/reports/<ID>/...).', 'nessusglpi'),
                self::SOURCE_WAS    => __('Use the WAS scan configuration UUID (Settings → Copy ID).', 'nessusglpi'),
            ],
            'i18n'        => [
                'invalidNumeric' => __('Tenable VM expects a numeric scan ID.', 'nessusglpi'),
                'invalidUuid'    => __('Tenable WAS expects a UUID (8-4-4-4-12 hex characters).', 'nessusglpi'),
                'previewLoading' => __('Querying Tenable…', 'nessusglpi'),
                'previewFailed'  => __('Unable to verify scan with Tenable.', 'nessusglpi'),
                'previewEmpty'   => __('Enter a scan ID first.', 'nessusglpi'),
                'previewOk'      => __('Scan found.', 'nessusglpi'),
                'previewLabelTargets'     => __('Targets', 'nessusglpi'),
                'previewLabelStatus'      => __('Status', 'nessusglpi'),
                'previewLabelFolder'      => __('Folder', 'nessusglpi'),
                'previewLabelOwner'       => __('Owner', 'nessusglpi'),
                'previewLabelLastUpdated' => __('Last updated', 'nessusglpi'),
            ],
        ];

        echo '<link rel="stylesheet" href="'
            . Html::cleanInputText($assetsBase . '/css/scan-form.css?v=' . $assetVersion) . '">';

        echo '<div class="nessus-scan-form-page" data-nessus-scan-form="'
            . htmlspecialchars((string) json_encode($jsState), ENT_QUOTES) . '">';

        // Hero
        echo '<header class="nessus-scan-form-hero">';
        echo '<div class="nessus-scan-form-hero__title-group">';
        echo '<a class="nessus-scan-form-hero__back" href="scan.php" title="' . Html::cleanInputText(__('Back to scan list', 'nessusglpi')) . '">'
            . $this->renderScanFormIcon('arrow-left') . '</a>';
        echo '<div>';
        echo '<h2 class="nessus-scan-form-hero__title">'
            . Html::cleanInputText($isNew ? __('Import a new scan', 'nessusglpi') : __('Edit scan', 'nessusglpi'))
            . '</h2>';
        echo '<p class="nessus-scan-form-hero__subtitle">'
            . Html::cleanInputText($isNew
                ? __('Connect a Tenable VM or WAS scan to start importing its hosts and vulnerabilities.', 'nessusglpi')
                : sprintf(__('Update the configuration of "%s".', 'nessusglpi'), $scanName !== '' ? $scanName : ('#' . $ID)))
            . '</p>';
        echo '</div>';
        echo '</div>';

        echo '<div class="nessus-scan-form-hero__actions">';
        echo '<a class="nessus-scan-form-btn nessus-scan-form-btn--ghost" href="scan.browser.php?source=' . self::SOURCE_NESSUS . '">'
            . $this->renderScanFormIcon('search') . '<span>'
            . Html::cleanInputText(__('Browse Tenable VM', 'nessusglpi')) . '</span></a>';
        echo '<a class="nessus-scan-form-btn nessus-scan-form-btn--ghost" href="scan.browser.php?source=' . self::SOURCE_WAS . '">'
            . $this->renderScanFormIcon('search') . '<span>'
            . Html::cleanInputText(__('Browse Tenable WAS', 'nessusglpi')) . '</span></a>';
        echo '</div>';
        echo '</header>';

        // Alert message
        if (is_string($message) && $message !== '') {
            $class = $messageType === 'error' ? 'nessus-scan-form-alert nessus-scan-form-alert--danger' : 'nessus-scan-form-alert nessus-scan-form-alert--info';
            echo '<div class="' . $class . '" role="alert">';
            echo $this->renderScanFormIcon($messageType === 'error' ? 'alert' : 'info');
            echo '<span>' . Html::cleanInputText($message) . '</span>';
            echo '</div>';
        }

        echo '<form method="post" action="' . static::getFormURL() . '" class="nessus-scan-form" novalidate>';

        // Card 1: Source + Scan ID + Preview
        echo '<section class="nessus-scan-form-card">';
        echo '<header class="nessus-scan-form-card__head">';
        echo '<div class="nessus-scan-form-card__icon nessus-scan-form-card__icon--source">'
            . $this->renderScanFormIcon('link') . '</div>';
        echo '<div class="nessus-scan-form-card__title-block">';
        echo '<h3 class="nessus-scan-form-card__title">'
            . Html::cleanInputText(__('Source & scan reference', 'nessusglpi')) . '</h3>';
        echo '<p class="nessus-scan-form-card__hint">'
            . Html::cleanInputText(__('Pick the Tenable product that hosts this scan, then paste its ID.', 'nessusglpi'))
            . '</p>';
        echo '</div>';
        echo '</header>';

        echo '<div class="nessus-scan-form-card__body">';

        // Source toggle
        echo '<div class="nessus-scan-form-field" data-nessus-scan-form-field="scan_type">';
        echo '<span class="nessus-scan-form-label">' . Html::cleanInputText(__('Source', 'nessusglpi')) . '</span>';
        echo '<div class="nessus-scan-form-source" role="radiogroup" aria-label="' . Html::cleanInputText(__('Source', 'nessusglpi')) . '">';
        foreach (static::getSourceOptions() as $source => $label) {
            $checked  = $source === $selectedSource;
            $modifier = $source === self::SOURCE_WAS ? 'was' : 'vm';
            echo '<label class="nessus-scan-form-source__option nessus-scan-form-source__option--' . Html::cleanInputText($modifier) . '"'
                . ($checked ? ' data-active="true"' : '') . '>';
            echo '<input type="radio" name="scan_type" value="' . Html::cleanInputText($source) . '"'
                . ($checked ? ' checked' : '')
                . ' data-nessus-scan-form-source>';
            echo '<span class="nessus-scan-form-source__icon">'
                . $this->renderScanFormIcon($source === self::SOURCE_WAS ? 'globe' : 'shield')
                . '</span>';
            echo '<span class="nessus-scan-form-source__label">' . Html::cleanInputText($label) . '</span>';
            echo '</label>';
        }
        echo '</div>';
        echo '</div>';

        // Scan ID + Verify button
        echo '<div class="nessus-scan-form-field" data-nessus-scan-form-field="scan_id">';
        echo '<label class="nessus-scan-form-label" for="nessus-scan-id-input">'
            . Html::cleanInputText(__('Scan ID', 'nessusglpi'))
            . ' <span class="nessus-scan-form-required" aria-hidden="true">*</span></label>';
        echo '<div class="nessus-scan-form-input-group">';
        echo '<input type="text" id="nessus-scan-id-input" name="scan_id" required'
            . ' value="' . Html::cleanInputText($scanIdValue) . '"'
            . ' autocomplete="off" spellcheck="false"'
            . ' data-nessus-scan-form-id'
            . ' class="nessus-scan-form-input">';
        echo '<button type="button" class="nessus-scan-form-btn nessus-scan-form-btn--ghost nessus-scan-form-btn--verify"'
            . ' data-nessus-scan-form-verify>'
            . $this->renderScanFormIcon('refresh')
            . '<span>' . Html::cleanInputText(__('Verify on Tenable', 'nessusglpi')) . '</span></button>';
        echo '</div>';
        echo '<p class="nessus-scan-form-hint" data-nessus-scan-form-hint></p>';
        echo '<p class="nessus-scan-form-feedback" data-nessus-scan-form-feedback hidden></p>';
        echo '</div>';

        // Preview card (populated by JS)
        echo '<div class="nessus-scan-form-preview" data-nessus-scan-form-preview hidden>';
        echo '<div class="nessus-scan-form-preview__head">';
        echo '<div class="nessus-scan-form-preview__icon">' . $this->renderScanFormIcon('check') . '</div>';
        echo '<div class="nessus-scan-form-preview__title-block">';
        echo '<strong class="nessus-scan-form-preview__title" data-nessus-scan-form-preview-name></strong>';
        echo '<span class="nessus-scan-form-preview__caption">' . Html::cleanInputText(__('Returned by Tenable API', 'nessusglpi')) . '</span>';
        echo '</div>';
        echo '</div>';
        echo '<dl class="nessus-scan-form-preview__meta" data-nessus-scan-form-preview-meta></dl>';
        echo '</div>';

        echo '</div>'; // card body
        echo '</section>';

        // Card 2: Import settings
        echo '<section class="nessus-scan-form-card">';
        echo '<header class="nessus-scan-form-card__head">';
        echo '<div class="nessus-scan-form-card__icon nessus-scan-form-card__icon--import">'
            . $this->renderScanFormIcon('filter') . '</div>';
        echo '<div class="nessus-scan-form-card__title-block">';
        echo '<h3 class="nessus-scan-form-card__title">'
            . Html::cleanInputText(__('Import settings', 'nessusglpi')) . '</h3>';
        echo '<p class="nessus-scan-form-card__hint">'
            . Html::cleanInputText(__('Pick which severity buckets should be imported into GLPI.', 'nessusglpi'))
            . '</p>';
        echo '</div>';
        echo '</header>';

        echo '<div class="nessus-scan-form-card__body">';

        echo '<div class="nessus-scan-form-field">';
        echo '<span class="nessus-scan-form-label">' . Html::cleanInputText(__('Imported severities', 'nessusglpi')) . '</span>';
        echo '<div class="nessus-scan-form-severities">';
        foreach (static::getSeverityOptions() as $severity => $label) {
            $checked  = in_array($severity, $selectedSeverities, true) ? ' checked' : '';
            $sevClass = strtolower($label);
            echo '<label class="nessus-scan-form-severity nessus-scan-form-severity--' . Html::cleanInputText($sevClass) . '">';
            echo '<input type="checkbox" name="import_severities[]" value="' . (int) $severity . '"' . $checked . '>';
            echo '<span class="nessus-scan-form-severity__dot"></span>';
            echo '<span class="nessus-scan-form-severity__label">' . Html::cleanInputText($label) . '</span>';
            echo '</label>';
        }
        echo '</div>';
        echo '<p class="nessus-scan-form-hint">'
            . Html::cleanInputText(__('Choose which severities will be imported during synchronization.', 'nessusglpi'))
            . '</p>';
        echo '</div>';

        echo '<div class="nessus-scan-form-meta-grid">';
        echo '<div class="nessus-scan-form-meta-item">';
        echo '<span class="nessus-scan-form-meta-item__label">' . Html::cleanInputText(__('Entity')) . '</span>';
        echo '<span class="nessus-scan-form-meta-item__value">' . Html::cleanInputText((string) $entityName) . '</span>';
        echo '</div>';
        if (!$isNew && $scanName !== '') {
            echo '<div class="nessus-scan-form-meta-item">';
            echo '<span class="nessus-scan-form-meta-item__label">' . Html::cleanInputText(__('Name')) . '</span>';
            echo '<span class="nessus-scan-form-meta-item__value">' . Html::cleanInputText($scanName) . '</span>';
            echo '</div>';
        }
        if (!$isNew && (int) ($this->fields['id'] ?? 0) > 0) {
            echo '<div class="nessus-scan-form-meta-item">';
            echo '<span class="nessus-scan-form-meta-item__label">' . Html::cleanInputText(__('GLPI ID', 'nessusglpi')) . '</span>';
            echo '<span class="nessus-scan-form-meta-item__value">#' . (int) ($this->fields['id'] ?? 0) . '</span>';
            echo '</div>';
        }
        echo '</div>';

        echo '</div>'; // card body
        echo '</section>';

        // Footer
        echo '<footer class="nessus-scan-form-footer">';
        echo Html::hidden('id', ['value' => $this->fields['id'] ?? 0]);
        echo Html::hidden('entities_id', ['value' => $entityId]);
        echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);

        echo '<a class="nessus-scan-form-btn nessus-scan-form-btn--ghost" href="scan.php">'
            . '<span>' . Html::cleanInputText(_sx('button', 'Cancel')) . '</span></a>';

        if ($canUpdate) {
            $submitName  = $isNew ? 'add' : 'update';
            $submitLabel = $isNew ? _sx('button', 'Add') : _sx('button', 'Save');
            echo '<button type="submit" name="' . Html::cleanInputText($submitName) . '" value="1"'
                . ' class="nessus-scan-form-btn nessus-scan-form-btn--primary">'
                . $this->renderScanFormIcon($isNew ? 'plus' : 'save')
                . '<span>' . Html::cleanInputText($submitLabel) . '</span></button>';
        } else {
            echo '<p class="nessus-scan-form-readonly">'
                . Html::cleanInputText(__('You do not have permission to modify this scan.', 'nessusglpi'))
                . '</p>';
        }
        echo '</footer>';

        Html::closeForm();
        echo '</div>'; // page

        echo '<script src="' . Html::cleanInputText($assetsBase . '/js/scan-form.js?v=' . $assetVersion) . '" defer></script>';

        return true;
    }

    private function renderScanFormIcon(string $name): string
    {
        $icons = [
            'arrow-left' => '<path d="M19 12H5"/><path d="m12 19-7-7 7-7"/>',
            'search'     => '<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>',
            'link'       => '<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
            'globe'      => '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 0 20"/><path d="M12 2a15.3 15.3 0 0 0 0 20"/>',
            'shield'     => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
            'refresh'    => '<path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/>',
            'check'      => '<polyline points="20 6 9 17 4 12"/>',
            'filter'     => '<polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"/>',
            'plus'       => '<path d="M12 5v14"/><path d="M5 12h14"/>',
            'save'       => '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
            'alert'      => '<path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
            'info'       => '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
        ];

        $inner = $icons[$name] ?? '<circle cx="12" cy="12" r="10"/>';
        return '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $inner . '</svg>';
    }

    public function prepareInputForAdd($input): array
    {
        $input['entities_id']       = (int) ($input['entities_id'] ?? Session::getActiveEntity());
        $input['scan_type']         = static::normalizeSource($input['scan_type'] ?? self::SOURCE_NESSUS);
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
        $input['scan_type']         = static::normalizeSource($input['scan_type'] ?? $this->fields['scan_type'] ?? self::SOURCE_NESSUS);
        $input['import_severities'] = array_key_exists('import_severities', $input)
            ? static::encodeImportSeverities($input['import_severities'])
            : (string) ($this->fields['import_severities'] ?? static::encodeImportSeverities(null));
        $input['is_active']         = (int) ($input['is_active'] ?? $this->fields['is_active'] ?? 1);
        $input['date_mod']          = date('Y-m-d H:i:s');
        $input['comment']           = $input['comment'] ?? $this->fields['comment'] ?? null;

        return $input;
    }
}
