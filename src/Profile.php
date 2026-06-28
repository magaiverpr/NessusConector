<?php

declare(strict_types=1);

namespace GlpiPlugin\Nessusglpi;

use CommonGLPI;
use Html;
use Profile as CoreProfile;
use Session;

class Profile extends CoreProfile
{
    public static function getAllRights(): array
    {
        return [
            [
                'itemtype' => Scan::class,
                'label'    => __('Nessus scans', 'nessusglpi'),
                'field'    => 'plugin_nessusglpi_scan',
                'rights'   => [READ, UPDATE, CREATE],
            ],
            [
                'itemtype' => Config::class,
                'label'    => __('Nessus configuration', 'nessusglpi'),
                'field'    => 'plugin_nessusglpi_config',
                'rights'   => [READ, UPDATE],
            ],
            [
                'itemtype' => Vulnerability::class,
                'label'    => __('Nessus vulnerabilities', 'nessusglpi'),
                'field'    => 'plugin_nessusglpi_vulnerability',
                'rights'   => [READ, UPDATE],
            ],
            [
                'itemtype' => Host::class,
                'label'    => __('Nessus host tickets', 'nessusglpi'),
                'field'    => 'plugin_nessusglpi_ticket',
                'rights'   => [READ, CREATE],
            ],
        ];
    }

    public static function ensureProfileRights(): void
    {
        global $DB;

        $rights = static::getAllRights();
        if ($rights === []) {
            return;
        }

        $fields = array_column($rights, 'field');
        $profiles = [];
        foreach ($DB->request([
            'SELECT' => ['id', 'name'],
            'FROM'   => 'glpi_profiles',
        ]) as $row) {
            $profileId = (int) ($row['id'] ?? 0);
            if ($profileId > 0) {
                $profiles[$profileId] = (string) ($row['name'] ?? '');
            }
        }

        if ($profiles === []) {
            return;
        }

        $existing = [];
        foreach ($DB->request([
            'SELECT' => ['id', 'profiles_id', 'name', 'rights'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => [
                'name' => $fields,
            ],
        ]) as $row) {
            $existing[(int) $row['profiles_id'] . '|' . (string) $row['name']] = [
                'id'     => (int) $row['id'],
                'rights' => (int) ($row['rights'] ?? 0),
            ];
        }

        foreach ($profiles as $profileId => $profileName) {
            foreach ($rights as $right) {
                $field = (string) $right['field'];
                $key = $profileId . '|' . $field;
                $defaultRights = static::getDefaultRightsForProfile($profileName, $right['rights']);
                if (isset($existing[$key])) {
                    if ($defaultRights > 0 && $existing[$key]['rights'] === 0) {
                        $DB->update('glpi_profilerights', [
                            'rights' => $defaultRights,
                        ], [
                            'id' => $existing[$key]['id'],
                        ]);
                    }
                    continue;
                }

                $DB->insert('glpi_profilerights', [
                    'profiles_id' => $profileId,
                    'name'        => $field,
                    'rights'      => $defaultRights,
                ]);
            }
        }
    }

    private static function getDefaultRightsForProfile(string $profileName, array $allowedRights): int
    {
        if (strcasecmp($profileName, 'Super-Admin') !== 0) {
            return 0;
        }

        $mask = 0;
        foreach ($allowedRights as $right) {
            $mask |= (int) $right;
        }

        return $mask;
    }

    public static function saveRightsForProfile(int $profileId, array $submittedRights): void
    {
        global $DB;

        if ($profileId <= 0) {
            return;
        }

        foreach (static::getAllRights() as $right) {
            $field = (string) $right['field'];
            $selected = isset($submittedRights[$field]) && is_array($submittedRights[$field])
                ? array_map('intval', $submittedRights[$field])
                : [];

            $mask = 0;
            foreach ($right['rights'] as $value) {
                $value = (int) $value;
                if (in_array($value, $selected, true)) {
                    $mask |= $value;
                }
            }

            $existing = $DB->request([
                'SELECT' => ['id'],
                'FROM'   => 'glpi_profilerights',
                'WHERE'  => [
                    'profiles_id' => $profileId,
                    'name'        => $field,
                ],
                'LIMIT' => 1,
            ])->current();

            if ($existing) {
                $DB->update('glpi_profilerights', [
                    'rights' => $mask,
                ], [
                    'id' => (int) $existing['id'],
                ]);
            } else {
                $DB->insert('glpi_profilerights', [
                    'profiles_id' => $profileId,
                    'name'        => $field,
                    'rights'      => $mask,
                ]);
            }
        }
    }

    public static function getCurrentRightsForProfile(int $profileId): array
    {
        global $DB;

        $result = [];
        if ($profileId <= 0) {
            return $result;
        }

        $fields = array_column(static::getAllRights(), 'field');
        foreach ($DB->request([
            'SELECT' => ['name', 'rights'],
            'FROM'   => 'glpi_profilerights',
            'WHERE'  => [
                'profiles_id' => $profileId,
                'name'        => $fields,
            ],
        ]) as $row) {
            $result[(string) $row['name']] = (int) ($row['rights'] ?? 0);
        }

        return $result;
    }

    public static function syncCurrentProfileRights(): void
    {
        global $DB;

        if (
            !isset($DB)
            || !isset($_SESSION['glpiactiveprofile'])
            || !is_array($_SESSION['glpiactiveprofile'])
        ) {
            return;
        }

        $profileId = (int) ($_SESSION['glpiactiveprofile']['id'] ?? 0);
        if ($profileId <= 0 || !$DB->tableExists('glpi_profilerights')) {
            return;
        }

        foreach (static::getCurrentRightsForProfile($profileId) as $field => $rights) {
            $_SESSION['glpiactiveprofile'][$field] = $rights;
        }
    }

    public static function getIcon(): string
    {
        return 'ti ti-shield-search';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0): string
    {
        if ($item instanceof CoreProfile) {
            return self::createTabEntry(__('Nessus Conector', 'nessusglpi'), 0, null, self::getIcon());
        }

        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0): bool
    {
        global $CFG_GLPI;

        if (!$item instanceof CoreProfile) {
            return true;
        }

        $profileId     = (int) $item->getID();
        $currentRights = static::getCurrentRightsForProfile($profileId);
        $canEdit       = Session::haveRight('profile', UPDATE) > 0;

        $assetsBase    = ($CFG_GLPI['root_doc'] ?? '') . '/plugins/nessusglpi';
        $assetVersion  = defined('PLUGIN_NESSUSGLPI_VERSION') ? PLUGIN_NESSUSGLPI_VERSION : '1';

        $permissionLabels = [
            READ   => 'READ',
            UPDATE => 'UPDATE',
            CREATE => 'CREATE',
        ];
        $permissionHints = [
            READ   => __('View entries', 'nessusglpi'),
            UPDATE => __('Edit / sync / delete', 'nessusglpi'),
            CREATE => __('Add new entries / tickets', 'nessusglpi'),
        ];

        echo '<link rel="stylesheet" href="'
            . Html::cleanInputText($assetsBase . '/css/scan-form.css?v=' . $assetVersion) . '">';

        echo '<div class="nessus-scan-form-page">';

        echo '<header class="nessus-scan-form-hero">';
        echo '<div class="nessus-scan-form-hero__title-group">';
        echo '<div>';
        echo '<h2 class="nessus-scan-form-hero__title">'
            . Html::cleanInputText(__('Plugin rights', 'nessusglpi')) . '</h2>';
        echo '<p class="nessus-scan-form-hero__subtitle">'
            . Html::cleanInputText(__('Control which actions members of this profile can perform on Nessus Conector resources.', 'nessusglpi'))
            . '</p>';
        echo '</div>';
        echo '</div>';
        echo '</header>';

        echo '<form method="post" action="/plugins/nessusglpi/front/profile.rights.php" class="nessus-scan-form">';
        echo Html::hidden('profiles_id', ['value' => $profileId]);
        echo Html::hidden('_glpi_csrf_token', ['value' => Session::getNewCSRFToken()]);

        echo '<section class="nessus-scan-form-card">';
        echo '<header class="nessus-scan-form-card__head">';
        echo '<div class="nessus-scan-form-card__icon nessus-scan-form-card__icon--source">'
            . static::renderProfileIcon('shield') . '</div>';
        echo '<div class="nessus-scan-form-card__title-block">';
        echo '<h3 class="nessus-scan-form-card__title">'
            . Html::cleanInputText(__('Resource permissions', 'nessusglpi')) . '</h3>';
        echo '<p class="nessus-scan-form-card__hint">'
            . Html::cleanInputText(__('Tick the permissions to grant. Unchecked permissions are denied.', 'nessusglpi'))
            . '</p>';
        echo '</div>';
        echo '</header>';

        echo '<div class="nessus-scan-form-card__body" style="gap:0.6rem;">';

        foreach (static::getAllRights() as $right) {
            $field = (string) $right['field'];
            $mask  = (int) ($currentRights[$field] ?? 0);

            echo '<div class="nessus-profile-rights__row" style="display:grid; grid-template-columns: minmax(0, 1fr) auto; gap: 1rem; align-items:center; padding:0.85rem 1rem; border:1px solid var(--nessus-border); border-radius: var(--nessus-radius-sm); background: var(--nessus-surface);">';

            echo '<div>';
            echo '<strong style="display:block; font-size:0.95rem; font-weight:600;">' . Html::cleanInputText((string) $right['label']) . '</strong>';
            echo '<code style="font-size:0.78rem; color:var(--nessus-muted); background:var(--nessus-surface-soft); padding:2px 6px; border-radius:4px;">'
                . Html::cleanInputText($field) . '</code>';
            echo '</div>';

            echo '<div style="display:flex; flex-wrap:wrap; gap:0.4rem; justify-content:flex-end;">';
            foreach ([READ, UPDATE, CREATE] as $permission) {
                $label = $permissionLabels[$permission];
                $hint  = $permissionHints[$permission];

                if (!in_array($permission, $right['rights'], true)) {
                    echo '<span class="nessus-scan-form-severity" style="opacity:0.35; cursor:not-allowed; color:var(--nessus-muted);" title="' . Html::cleanInputText(__('Not available', 'nessusglpi')) . '">';
                    echo '<span class="nessus-scan-form-severity__dot"></span>';
                    echo '<span class="nessus-scan-form-severity__label">' . Html::cleanInputText($label) . '</span>';
                    echo '</span>';
                    continue;
                }

                $checked  = ($mask & $permission) === $permission;
                $sevClass = match ($permission) {
                    READ   => 'info',
                    UPDATE => 'medium',
                    CREATE => 'low',
                    default => 'info',
                };
                echo '<label class="nessus-scan-form-severity nessus-scan-form-severity--' . $sevClass . '" title="' . Html::cleanInputText($hint) . '">';
                echo '<input type="checkbox" name="plugin_nessusglpi_rights[' . Html::cleanInputText($field) . '][]" value="' . (int) $permission . '"'
                    . ($checked ? ' checked' : '')
                    . ($canEdit ? '' : ' disabled') . '>';
                echo '<span class="nessus-scan-form-severity__dot"></span>';
                echo '<span class="nessus-scan-form-severity__label">' . Html::cleanInputText($label) . '</span>';
                echo '</label>';
            }
            echo '</div>';

            echo '</div>';
        }

        echo '</div>'; // /card body
        echo '</section>';

        echo '<footer class="nessus-scan-form-footer">';
        if ($canEdit) {
            echo '<button type="submit" name="save_nessusglpi_rights" value="1"'
                . ' class="nessus-scan-form-btn nessus-scan-form-btn--primary">'
                . static::renderProfileIcon('save')
                . '<span>' . Html::cleanInputText(__('Save')) . '</span></button>';
        } else {
            echo '<p class="nessus-scan-form-readonly">'
                . Html::cleanInputText(__('You do not have permission to modify these rights.', 'nessusglpi'))
                . '</p>';
        }
        echo '</footer>';

        Html::closeForm();
        echo '</div>'; // /page

        return true;
    }

    private static function renderProfileIcon(string $name): string
    {
        $icons = [
            'shield' => '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
            'save'   => '<path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/>',
        ];
        $inner = $icons[$name] ?? '<circle cx="12" cy="12" r="10"/>';
        return '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' . $inner . '</svg>';
    }
}
